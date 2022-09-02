;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/x509.sls - X.509 certificate APIs
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
(library (springkussen x509)
    (export x509-certificate?
	    read-x509-certificate
	    bytevector->x509-certificate
	    write-x509-certificate
	    x509-certificate->bytevector

	    x509-certificate:public-key
	    x509-certificate:version
	    x509-certificate:serial-number
	    x509-certificate:signature
	    x509-certificate:issuer
	    x509-certificate:validity
	    x509-certificate:subject
	    x509-certificate:issuer-unique-id
	    x509-certificate:subject-unique-id
	    x509-certificate:extensions
	    x509-certificate:signature-algorithm
	    x509-certificate:validate
	    make-x509-signature-validator

	    make-x509-validity x509-validity?
	    make-x509-time x509-time?
	    x509-name?
	    make-x509-distinguished-names
	    x509-distinguished-names->string
	    string->x509-distinguished-names
	    (rename (*rfc5280-symbols* *x509:rfc5280-names*))

	    make-x509-self-signed-certificate

	    ;; CSR
	    x509-certificate-signing-request?
	    x509-certificate-signing-request:subject
	    x509-certificate-signing-request:subject-pk-info
	    x509-certificate-signing-request:sign
	    read-x509-certificate-signing-request
	    bytevector->x509-certificate-signing-request
	    write-x509-certificate-signing-request
	    x509-certificate-signing-request->bytevector

	    x509-certificate-signing-request-builder?
	    x509-certificate-signing-request-builder-builder
	    x509-certificate-signing-request-builder:build

	    make-x509-attributes x509-attributes?
	    x509-attributes
	    
	    x509-attribute?
	    make-x509-challenge-password-attribute
	    x509-challenge-password-attribute?
	    make-x509-extension-request-attribute
	    x509-extension-request-attribute?

	    ;; CRL
	    x509-certificate-revocation-list?
	    read-x509-certificate-revocation-list
	    bytevector->x509-certificate-revocation-list
	    write-x509-certificate-revocation-list
	    x509-certificate-revocation-list->bytevector

	    x509-certificate-revocation-list:certificate-revoked?
	    x509-certificate-revocation-list:signed?
	    x509-certificate-revocation-list:sign
	    x509-certificate-revocation-list:revoked-certificates
	    x509-certificate-revocation-list:issuer
	    x509-certificate-revocation-list:add-revoked-certificates

	    x509-certificate-revocation-list-builder?
	    x509-certificate-revocation-list-builder-builder
	    x509-certificate-revocation-list-builder:build

	    x509-revoked-certificate?
	    make-x509-revoked-certificate

	    ;; Extensions
	    make-x509-extensions x509-extensions? x509-extensions
	    x509-extensions-length x509-extensions-elements

	    x509-extension?
	    make-x509-authority-key-identifier-extension
	    x509-authority-key-identifier-extension?
	    
	    make-x509-general-names x509-general-names? x509-general-names

	    x509-general-name?
	    other-name->x509-general-name
	    rfc822-name->x509-general-name
	    dns-name->x509-general-name
	    directory-name->x509-general-name
	    uniform-resource-identifier->x509-general-name
	    ip-address->x509-general-name
	    registered-id->x509-general-name
	    
	    make-x509-authority-key-identifier x509-authority-key-identifier?
	    x509-authority-key-identifier-key-identifier
	    x509-authority-key-identifier-authority-cert-issuer
	    x509-authority-key-identifier-serial-number
	    
	    describe-x509-certificate
	    )
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen conditions)
	    (springkussen misc bytevectors)
	    (springkussen misc lambda)
	    (springkussen misc record)
	    (springkussen signature)
	    (rename (springkussen x509 types)
		    (make-x509-time t:make-x509-time))
	    (springkussen x509 extensions)
	    (rename (springkussen x509 certificate)
		    (make-x509-validity c:make-x509-validity))
	    (springkussen x509 request)
	    (rename (springkussen x509 revocation)
		    (make-x509-revoked-certificate
		     r:make-x509-revoked-certificate))
	    (springkussen x509 signature))

(define (x509-extensions . e*) (make-x509-extensions e*))
(define (x509-general-names . gn*) (make-x509-general-names gn*))

(define (x509-extensions-length e)
  (length (asn1-collection-elements e)))
(define (x509-extensions-elements e) (asn1-collection-elements e))

(define (x509-attributes . a*) (make-x509-attributes a*))

(define (make-x509-validity not-before not-after)
  (c:make-x509-validity (make-x509-time not-before) (make-x509-time not-after)))

(define (make-x509-time time) (t:make-x509-time (make-der-utc-time time)))

(define (make-x509-distinguished-names . n) (list->x509-name n))
(define x509-distinguished-names->string x509-name->string)
(define string->x509-distinguished-names string->x509-name)

(define make-x509-self-signed-certificate
  (case-lambda/typed
   ((key-pair sn subject validity)
    (make-x509-self-signed-certificate key-pair sn subject validity #f))
   (((key-pair key-pair?) (sn integer?) (subject x509-name?)
     (validity x509-validity?) (extensions (or #f x509-extensions?)))
    (define (make-tbs sn signature subject validity public-key extensions)
      (define version (and extensions (make-der-integer 2)))
      (make-x509-tbs-certificate
       #f
       version
       (make-der-integer sn)
       signature
       subject
       validity
       subject
       (public-key->subject-public-key-info public-key)
       #f
       #f
       extensions))
    (let* ((private-key (key-pair-private key-pair))
	   (sa (make-x509-default-signature-algorithm private-key))
	   (signer ((signature-algorithm->signer-creator sa) private-key))
	   (tbs (make-tbs sn sa subject validity
			  (key-pair-public key-pair) extensions))
	   (signing-content (asn1-object->bytevector tbs))
	   (sig (signer:sign-message signer signing-content)))
      (make-x509-certificate
       (make-x509-certificate-structure
	tbs sa (make-der-bit-string sig) #f))))))

(define-record-type x509-certificate-signing-request-builder
  (fields key-pair
	  subject
	  attributes
	  signature-algorithm-retriever))
(define-syntax x509-certificate-signing-request-builder-builder
  (make-record-builder x509-certificate-signing-request-builder
   ((signature-algorithm-retriever make-x509-default-signature-algorithm))))

(define x509-csr-builder-key-pair
  x509-certificate-signing-request-builder-key-pair)
(define x509-csr-builder-subject
  x509-certificate-signing-request-builder-subject)
(define x509-csr-builder-attributes
  x509-certificate-signing-request-builder-attributes)
(define x509-csr-builder-sa-retriever
  x509-certificate-signing-request-builder-signature-algorithm-retriever)

(define/typed (x509-certificate-signing-request-builder:build
	       (builder x509-certificate-signing-request-builder?))
  (let* ((kp (x509-csr-builder-key-pair builder))
	 (ctr (x509-csr-builder-sa-retriever builder))
	 (cri (make-x509-certification-request-info
	       (make-der-integer 0) ;; Only 0 is defined...
	       (x509-csr-builder-subject builder)
	       (public-key->subject-public-key-info (key-pair-public kp))
	       (x509-csr-builder-attributes builder)))
	 (signing-content (asn1-object->bytevector cri))
	 (private-key (key-pair-private kp))
	 (sa (ctr private-key))
	 (signer ((signature-algorithm->signer-creator sa) private-key))
	 (sig (signer:sign-message signer signing-content)))
    (make-x509-certificate-signing-request 
     (make-x509-certification-request cri sa (make-der-bit-string sig)))))

(define make-x509-revoked-certificate
  (case-lambda/typed
   (((serial-number integer?) (revocation-date x509-time?))
    (r:make-x509-revoked-certificate
     (make-der-integer serial-number) revocation-date #f))
   (((serial-number integer?) (revocation-date x509-time?)
     (extensions x509-extensions?))
    (r:make-x509-revoked-certificate
     (make-der-integer serial-number) revocation-date extensions))))

(define-record-type x509-certificate-revocation-list-builder
  (fields issuer
	  this-update
	  next-update
	  revoked-certificates
	  extensions
	  signature-algorithm-retriever))
(define-syntax x509-certificate-revocation-list-builder-builder
  (make-record-builder x509-certificate-revocation-list-builder
   ((revoked-certificates '())
    (signature-algorithm-retriever make-x509-default-signature-algorithm))))

(define/typed (x509-certificate-revocation-list-builder:build
	       (builder x509-certificate-revocation-list-builder?)
	       (private-key private-key?))
  ;; I'm lazy to check v1 or v2 by checking presence of extensions both
  ;; CRL and revoked cert, so just use v2...
  (let ((tbs (make-x509-tbs-cert-list
	      (make-der-integer 1) #f
	      (x509-certificate-revocation-list-builder-issuer builder)
	      (x509-certificate-revocation-list-builder-this-update builder)
	      (x509-certificate-revocation-list-builder-next-update builder)
	      (make-der-sequence
	       (x509-certificate-revocation-list-builder-revoked-certificates
		builder))
	      (x509-certificate-revocation-list-builder-extensions builder))))
    (x509-certificate-revocation-list:sign
     (make-x509-certificate-revocation-list
      (make-x509-certificate-list tbs #f #f)) private-key)))

;; Misc
(define describe-x509-certificate
  (case-lambda
   ((x509-certificate)
    (describe-x509-certificate x509-certificate (current-output-port)))
   ((x509-certificate out)
    (describe-x509-certificate x509-certificate out 0))
   ((x509-certificate out indent)
    (unless (x509-certificate? x509-certificate)
      (springkussen-assertion-violation 'describe-x509-certificate
					"X509 certificate is required"
					x509-certificate))
    (describe-x509 x509-certificate out indent))))

(define (describe-x509 cert out indent)
  (define (put-indent)
    (do ((i 0 (+ i 1))) ((= i (* indent 2))) (put-char out #\space)))
  (define (ps msg) (put-indent) (put-string out msg))
  (define (nl) (newline out))
  (define (pl msg) (ps msg) (nl))
  (define (n num) (put-string out (number->string num)))
  (define (s str) (put-string out str))
  (define (d datum) (put-datum out datum))
  (define (dn lis)
    (do ((lis lis (cdr lis)) (first? #t #f))
	((null? lis))
      (let* ((e (car lis))
	     (a (car e))
	     (v (cadr e)))
	(unless first? (s ", "))
	(d a) (put-char out #\=) (d v))))
  (let-values (((not-before not-after) (x509-certificate:validity cert)))
    (pl "X509 Certificate")
    (ps "  [0]         Version: ") (n (x509-certificate:version cert)) (nl)
    (ps "         SerialNumber: ") (n (x509-certificate:serial-number cert)) (nl)
    (ps "             IssuerDN: ") (dn (x509-certificate:issuer cert)) (nl)
    (ps "           Start Date: ") (d not-before) (nl)
    (ps "             End Date: ") (d not-after) (nl)
    (ps "            SbuejctDN: ") (dn (x509-certificate:subject cert)) (nl)
    (pl "           Public Key: ")
    ;; TODO
    ;; (describe-asymmetric-key (x509-certificate:public-key cert) out 5)
    (ps "  Signature Algorithm: ")
    (describe-asn1-object (x509-certificate:signature-algorithm cert) out 11)
    (ps "            Signature: ")
    (ps (bytevector->hex-string (x509-certificate:signature cert))) (nl)
    (let ((extensions (x509-certificate:extensions cert)))
      (when extensions
	(pl "  [3]      Extensions: ")
	(describe-x509-extensions extensions out 11)))))
)
