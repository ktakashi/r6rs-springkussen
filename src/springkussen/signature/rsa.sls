;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/signature/rsa.sls - RSA signer/verifier
;;;  
;;;   Copyright (c) 2022  Takashi Kato  <ktakashi@ymail.com>
;;;   
;;;   Redistribution and use in source and binary forms, with or without
;;;   modification, are permitted provided that the following conditions
;;;   are met:
;;;   
;;;   1. Redistributions of source code must retain the above copyright
;;;      notice, this list of conditions and the following disclaimer.
;;;  
;;;   2. Redistributions in binary form must reproduce the above copyright
;;;      notice, this list of conditions and the following disclaimer in the
;;;      documentation and/or other materials provided with the distribution.
;;;  
;;;   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;;;   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;;;   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;;;   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;;;   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;;;   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
;;;   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;;;   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;;;   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;;   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;;   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;  

#!r6rs
(library (springkussen signature rsa)
    (export rsa-signer-descriptor
	    make-rsa-signature-encode-parameter rsa-signature-encode-parameter?
	    pkcs1-emsa-v1.5-encode

	    rsa-verifier-descriptor
	    make-rsa-signature-verify-parameter rsa-signature-verify-parameter?
	    pkcs1-emsa-v1.5-verify
	    )
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen cipher asymmetric)
	    (springkussen cipher asymmetric scheme rsa)
	    (springkussen conditions)
	    (springkussen digest)
	    (springkussen misc bytevectors)
	    (springkussen signature descriptor)
	    (springkussen signature parameters))

(define-signature-parameter <rsa-signaturre-encode-parameter>
  make-rsa-signature-encode-parameter rsa-signature-encode-parameter?
  (encoder signature-parameter-encoder))

(define-record-type rsa-signer-state
  (fields key
	  md
	  digester
	  encoder))

(define (rsa-sign-init key param)
  (unless (rsa-private-key? key)
    (springkussen-assertion-violation 'signer-init
				      "Signer requires private key"))
  (let* ((md (signature-parameter-md param *digest:sha256*))
	 ;; TODO use PSS, but for now
	 (encoder ((signature-parameter-encoder param pkcs1-emsa-v1.5-encode) param))
	 (digester (make-digester md)))
    (unless (digest-descriptor-oid md)
      (springkussen-assertion-violation 'signer-init
       "Given digest algorithm doesn't have OID" md))
    (digester:init! digester)
    (make-rsa-signer-state key md digester encoder)))

(define (rsa-sign-process state bv start end)
  (digester:process! (rsa-signer-state-digester state) bv start end))

(define (rsa-sign-done state)
  (let ((cipher (make-asymmetric-cipher
		 (asymmetric-cipher-spec-builder
		  (scheme *scheme:rsa*)
		  ;; no encoding
		  (encoding (lambda ignore (values #f #f))))
		 (rsa-signer-state-key state)))
	(encoder (rsa-signer-state-encoder state))
	(digester (rsa-signer-state-digester state))
	(key (rsa-signer-state-key state)))
    (asymmetric-cipher:encrypt-bytevector cipher
     (encoder (rsa-private-key-modulus key) (digester:done digester)))))

;; I believe these encodings are only for RSA
(define (pkcs1-emsa-v1.5-encode param)
  (define md (signature-parameter-md param *digest:sha256*))
  (define oid (digest-descriptor-oid md))
  (lambda (modulus m)
    (let* ((em-len (div (+ (bitwise-length modulus) 7) 8))
	   (digest (der-sequence (der-sequence
				  (make-der-object-identifier oid)
				  (make-der-null))
				 (make-der-octet-string m)))
	   (T (asn1-object->bytevector digest))
	   (t-len (bytevector-length T)))
      (when (< em-len (+ t-len 11))
	(springkussen-error 'pkcs1-emsa-v1.5-encode
			    "Intended encoded message length too short"))
      (let* ((PS-len (- em-len t-len 3))
	     ;; Initialize with PS value
	     (EM (make-bytevector (+ PS-len 3 t-len) #xFF)))
	(bytevector-u8-set! EM 0 #x00)
	(bytevector-u8-set! EM 1 #x01)
	(bytevector-u8-set! EM (+ PS-len 2) #x00)
	(bytevector-copy! T 0 EM (+ PS-len 3) t-len) 
	EM))))


(define-signature-parameter <rsa-signature-verify-parameter>
  make-rsa-signature-verify-parameter rsa-signature-verify-parameter?
  (verify signature-parameter-verify))

(define rsa-signer-descriptor
  (signer-descriptor-builder
   (name "RSA")
   (initializer rsa-sign-init)
   (processor rsa-sign-process)
   (finalizer rsa-sign-done)))

(define (pkcs1-emsa-v1.5-verify param)
  (define encode (pkcs1-emsa-v1.5-encode param))
  (lambda (modulus m S)
    (let ((EM (encode modulus m)))
      (bytevector-safe=? EM S))))

(define (rsa-verify-init key param)
  (unless (rsa-public-key? key)
    (springkussen-assertion-violation 'verifier-init
				      "Verifier requires public key"))
  (let* ((md (signature-parameter-md param *digest:sha256*))
	 ;; TODO use PSS, but for now
	 (verifier ((signature-parameter-verify param pkcs1-emsa-v1.5-verify) param))
	 (digester (make-digester md)))
    (unless (digest-descriptor-oid md)
      (springkussen-assertion-violation 'verifier-init
       "Given digest algorithm doesn't have OID" md))
    (digester:init! digester)
    ;; we can reuse signer state :D
    (make-rsa-signer-state key md digester verifier)))

(define rsa-verify-process rsa-sign-process) ;; the same

(define (rsa-verify-done state S)
  (let ((cipher (make-asymmetric-cipher
		 (asymmetric-cipher-spec-builder
		  (scheme *scheme:rsa*)
		  (encoding (lambda ignore (values #f #f))))
		 (rsa-signer-state-key state)))
	(verifier (rsa-signer-state-encoder state))
	(digester (rsa-signer-state-digester state))
	(key (rsa-signer-state-key state)))
    ;; TODO do we want to check the signature length?
    (let ((EM (asymmetric-cipher:decrypt-bytevector cipher S)))
      (verifier (rsa-public-key-modulus key) (digester:done digester) EM))))

(define rsa-verifier-descriptor
  (verifier-descriptor-builder
   (name "RSA")
   (initializer rsa-verify-init)
   (processor rsa-verify-process)
   (finalizer rsa-verify-done)))

)
