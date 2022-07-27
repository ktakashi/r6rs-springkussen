;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/x509/signature.sls - Signer and verifier for X.509
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
(library (springkussen x509 signature)
    (export signature-algorithm->signer-creator
	    signature-algorithm->verifier-creator

	    make-x509-default-signature-algorithm)
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen conditions)
	    (springkussen digest)
	    (springkussen signature)
	    (springkussen x509 types))

(define digest-parameter (make-signature-digest-parameter *digest:sha256*))
(define rsa-signer-parameter
  (make-signature-parameter digest-parameter
   ;; Should we use PSS?
   (make-rsa-signature-encode-parameter pkcs1-emsa-v1.5-encode)))
(define ecdsa-signer-parameter
  (make-signature-parameter digest-parameter
    (make-ecdsa-encode-parameter (ecdsa-signature-encode-type der))))

(define (make-x509-default-signature-algorithm private-key)
  (make-algorithm-identifier
   (make-der-object-identifier
    (cond ((rsa-private-key? private-key) "1.2.840.113549.1.1.11")
	  ((ecdsa-private-key? private-key) "1.2.840.10045.4.3.2")
	  (else
	   (springkussen-assertion-violation
	    'private-key->x509-signer&signature-algorihtm
	    "Unknown private key type"))))
   (make-der-null)))

(define (signature-algorithm->signer-creator signature-algorithm)
  ;; TODO RSA-PSS
  (lambda (private-key)
    (cond ((rsa-private-key? private-key)
	   (make-signer *signer:rsa* private-key rsa-signer-parameter))
	  ((ecdsa-private-key? private-key)
	   (make-signer *signer:ecdsa* private-key ecdsa-signer-parameter))
	  (else
	   (springkussen-assertion-violation
	    'signature-algorithm->signer-creator
	    "Unknown private key type")))))

(define pkcs1-v1.5-verify
  (make-rsa-signature-verify-parameter pkcs1-emsa-v1.5-verify))
(define der-encode
  (make-ecdsa-encode-parameter (ecdsa-signature-encode-type der)))
(define sdp make-signature-digest-parameter)

(define *oid-verifier-parameter*
  `(("1.2.840.113549.1.1.5" ,*verifier:rsa*
     ,(make-signature-parameter pkcs1-v1.5-verify (sdp *digest:sha1*)))
    ("1.2.840.113549.1.1.11" ,*verifier:rsa*
     ,(make-signature-parameter pkcs1-v1.5-verify (sdp *digest:sha256*)))
    ("1.2.840.113549.1.1.12" ,*verifier:rsa*
     ,(make-signature-parameter pkcs1-v1.5-verify (sdp *digest:sha384*)))
    ("1.2.840.113549.1.1.13" ,*verifier:rsa*
     ,(make-signature-parameter pkcs1-v1.5-verify (sdp *digest:sha512*)))
    ("1.2.840.113549.1.1.14" ,*verifier:rsa*
     ,(make-signature-parameter pkcs1-v1.5-verify (sdp *digest:sha224*)))
    ("1.2.840.113549.1.1.15" ,*verifier:rsa*
     ,(make-signature-parameter pkcs1-v1.5-verify (sdp *digest:sha512/224*)))
    ("1.2.840.113549.1.1.16" ,*verifier:rsa*
     ,(make-signature-parameter pkcs1-v1.5-verify (sdp *digest:sha512/256*)))
    ;; ECDSA
    ("1.2.840.10045.4.1" ,*verifier:ecdsa*
     ,(make-signature-parameter der-encode (sdp *digest:sha1*)))
    ("1.2.840.10045.4.3.1" ,*verifier:ecdsa*
     ,(make-signature-parameter der-encode (sdp *digest:sha224*)))
    ("1.2.840.10045.4.3.2" ,*verifier:ecdsa*
     ,(make-signature-parameter der-encode (sdp *digest:sha256*)))
    ("1.2.840.10045.4.3.3" ,*verifier:ecdsa*
     ,(make-signature-parameter der-encode (sdp *digest:sha384*)))
    ("1.2.840.10045.4.3.4" ,*verifier:ecdsa*
     ,(make-signature-parameter der-encode (sdp *digest:sha512*)))))

(define (signature-algorithm->verifier-creator signature-algorithm)
  (define oid (algorithm-identifier-algorithm signature-algorithm))
  ;; TODO RSA-PSS
  (cond ((assoc (der-object-identifier-value oid) *oid-verifier-parameter*) =>
	 (lambda (slot)
	   (define desc (cadr slot))
	   (define param (caddr slot))
	   (lambda (public-key) (make-verifier desc public-key param))))
	(else
	 (springkussen-error 'signature-algorithm->verifier-creator
			     "Unknown signature OID"
			     (der-object-identifier-value oid)))))

)
