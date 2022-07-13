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
	    pkcs1-emsa-v1.5-encode pkcs1-emsa-pss-encode

	    rsa-verifier-descriptor
	    make-rsa-signature-verify-parameter rsa-signature-verify-parameter?
	    pkcs1-emsa-v1.5-verify pkcs1-emsa-pss-verify

	    make-rsa-signature-mgf-digest-parameter
	    rsa-signature-mgf-digest-parameter?
	    ;; in case MGF-2 or custom MGF is there
	    make-rsa-signature-mgf-parameter rsa-signature-mgf-parameter?
	    make-rsa-signature-salt-parameter rsa-signature-salt-parameter?
	    make-rsa-signature-salt-length-parameter
	    rsa-signature-salt-length-parameter?
	    )
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen cipher asymmetric)
	    (springkussen cipher asymmetric scheme rsa)
	    (springkussen cipher asymmetric encoding) ;; for MGF-1
	    (springkussen conditions)
	    (springkussen digest)
	    (springkussen misc bytevectors)
	    (springkussen random)
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
	 (encoder ((signature-parameter-encoder param pkcs1-emsa-pss-encode)
		   param))
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


(define-signature-parameter <rsa-signature-verify-parameter>
  make-rsa-signature-verify-parameter rsa-signature-verify-parameter?
  (verify signature-parameter-verify))

(define rsa-signer-descriptor
  (signer-descriptor-builder
   (name "RSA")
   (initializer rsa-sign-init)
   (processor rsa-sign-process)
   (finalizer rsa-sign-done)))

(define (rsa-verify-init key param)
  (unless (rsa-public-key? key)
    (springkussen-assertion-violation 'verifier-init
				      "Verifier requires public key"))
  (let* ((md (signature-parameter-md param *digest:sha256*))
	 (verifier ((signature-parameter-verify param pkcs1-emsa-pss-verify)
		    param))
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

(define (pkcs1-emsa-v1.5-verify param)
  (define encode (pkcs1-emsa-v1.5-encode param))
  (lambda (modulus m S)
    (let ((EM (encode modulus m)))
      (bytevector-safe=? EM S))))

;; EMSA-PSS-ENCODE
(define-signature-parameter <rsa-signaturre-mgf-digest-parameter>
  make-rsa-signature-mgf-digest-parameter rsa-signature-mgf-digest-parameter?
  (mgf-digest signature-parameter-mgf-digest))
(define-signature-parameter (<rsa-signaturre-mgf-parameter> <rsa-signaturre-mgf-digest-parameter>)
  make-rsa-signature-mgf-parameter rsa-signature-mgf-parameter?
  (mgf signature-parameter-mgf))

(define-signature-parameter <rsa-signaturre-salt-parameter>
  make-rsa-signature-salt-parameter rsa-signature-salt-parameter?
  (salt signature-parameter-salt))

(define (default-salt size)
  (random-generator:read-random-bytes default-random-generator size))

(define (pkcs1-emsa-pss-encode param)
  (define md (signature-parameter-md param *digest:sha256*))
  (define digest-size (digest-descriptor-digest-size md))
  (define salt (or (signature-parameter-salt param #f)
		   (default-salt digest-size)))
  (define salt-len (bytevector-length salt))
  (define mgf (signature-parameter-mgf param mgf-1))
  (define mgf-md (signature-parameter-mgf-digest param *digest:sha1*))
  
  (lambda (modulus m)
    (define em-bits (bitwise-length modulus))
    (define em-len (div (+ em-bits 7) 8))
    (when (< em-len (+ digest-size salt-len 2))
      (springkussen-assertion-violation 'pkcs1-emsa-pss-encode
	"Intended encoded message length too short"))
    (let ((m-dash (make-bytevector (+ digest-size salt-len 8) 0)))
      ;; M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
      (bytevector-copy! m 0 m-dash 8 digest-size)
      (bytevector-copy! salt 0 m-dash (+ 8 digest-size) salt-len)
      (let* ((H (digester:digest (make-digester md) m-dash))
	     (PS-len (- em-len salt-len digest-size 2))
	     (PS (make-bytevector PS-len 0))
	     (DB (make-bytevector (+ PS-len salt-len 1) #x01)))
	(bytevector-copy! PS 0 DB 0 PS-len)
	(bytevector-copy! salt 0 DB (+ PS-len 1) salt-len)
	(let* ((db-mask (mgf H (- em-len digest-size 1) mgf-md))
	       (masked-db (bytevector-xor! DB 0 db-mask 0
					   (bytevector-length DB)))
	       (bit-mask (bitwise-arithmetic-shift-right
			  #xFF (- (* em-len 8) em-bits))))
	  (bytevector-u8-set! masked-db 0
			      (bitwise-and (bytevector-u8-ref masked-db 0)
					   bit-mask))
	  (let* ((m-len (bytevector-length masked-db))
		 (h-len (bytevector-length H))
		 (EM (make-bytevector (+ m-len h-len 1) #xBC)))
	    (bytevector-copy! masked-db 0 EM 0 m-len)
	    (bytevector-copy! H 0 EM m-len h-len)
	    EM))))))

(define-signature-parameter <rsa-signaturre-salt-length-parameter>
  make-rsa-signature-salt-length-parameter rsa-signature-salt-length-parameter?
  (salt-length signature-parameter-salt-length))

(define (pkcs1-emsa-pss-verify param)
  (define md (signature-parameter-md param *digest:sha256*))
  (define digest-size (digest-descriptor-digest-size md))
  (define salt-len (or (signature-parameter-salt-length param #f)
		       digest-size))
  (define mgf (signature-parameter-mgf param mgf-1))
  (define mgf-md (signature-parameter-mgf-digest param *digest:sha1*))

  (lambda (modulus m EM)
    (define (check-zero bv limit)
      (let loop ((i 0) (ok? #t))
	(if (= i limit)
	    ok?
	    (loop (+ i 1) (and (zero? (bytevector-u8-ref bv i)) ok?)))))
    (define em-bits (bitwise-length modulus))
    (define em-len (div (+ em-bits 7) 8))
    
    ;; we do entire step here to prevent oracle attack
    (let* ((mask-length (- em-len digest-size 1))
	   (masked-db (make-bytevector mask-length 0))
	   (H (make-bytevector digest-size 0))
	   (bit-mask (bitwise-arithmetic-shift-right
		      #xFF (- (* 8 em-len) em-bits))))
      (bytevector-copy! EM 0 masked-db 0 mask-length)
      (bytevector-copy! EM mask-length H 0 digest-size)
      (let* ((db-mask (mgf H mask-length mgf-md))
	      ;; we need masked-db to check at the last step
	     (mdb-copy (bytevector-copy masked-db))
	     (DB (bytevector-xor! mdb-copy 0 db-mask 0 mask-length))
	     (limit2 (- em-len digest-size salt-len 2)))
	(bytevector-u8-set! DB 0
			    (bitwise-and (bytevector-u8-ref DB 0)
					 (bitwise-not bit-mask)))
	(let ((check0 (check-zero DB limit2))
	      (check1 (= #x01 (bytevector-u8-ref DB limit2)))
	      (m-dash (make-bytevector (+ 8 digest-size salt-len) 0)))
	  (bytevector-copy! m 0 m-dash 8 digest-size)
	  (bytevector-copy! DB (- (bytevector-length DB) salt-len)
			    m-dash (+ 8 digest-size) salt-len)
	  (let ((h-dash (digester:digest (make-digester md) m-dash)))
	    (and (bytevector-safe=? H h-dash) ;; longest, do it first
		 (not (< em-len (+ digest-size salt-len 2)))
		 (= #xBC (bytevector-u8-ref EM (- (bytevector-length EM) 1)))
		 (zero? (bitwise-and (bytevector-u8-ref masked-db 0)
				     (bitwise-not bit-mask)))
		 check0
		 check1)))))))

)
