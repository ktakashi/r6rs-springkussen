;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/x509/request.sls - X.509 Certificate Signing Request
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

;; ref: https://datatracker.ietf.org/doc/html/rfc2985
#!r6rs
(library (springkussen x509 request)
    (export make-x509-certificate-signing-request
	    x509-certificate-signing-request?
	    x509-certificate-signing-request:subject
	    x509-certificate-signing-request:subject-pk-info
	    x509-certificate-signing-request:sign
	    read-x509-certificate-signing-request
	    bytevector->x509-certificate-signing-request

	    make-x509-attribute x509-attribute?
	    x509-attribute-type x509-attribute-values
	    x509-attribute->asn1-object

	    make-x509-attributes x509-attributes?
	    (rename (asn1-collection-elements x509-attributes-values))
	    
	    make-x509-certification-request-info
	    x509-certification-request-info?
	    x509-certification-request-info-version
	    x509-certification-request-info-subject
	    x509-certification-request-info-subject-pk-info
	    x509-certification-request-info-attributes
	    x509-certification-request-info->asn1-object
	    asn1-object->x509-certification-request-info

	    make-x509-certification-request x509-certification-request?
	    x509-certification-request-certification-request-info
	    x509-certification-request-signature-algorithm
	    x509-certification-request-signature
	    x509-certification-request->asn1-object
	    asn1-object->x509-certification-request
	    )
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen conditions)
	    (springkussen digest)
	    (springkussen misc bytevectors)
	    (springkussen signature)
	    (springkussen x509 types)
	    (springkussen x509 certificate))

(define-record-type x509-attribute
  (parent <asn1-encodable-object>)
  (fields type values)
  (protocol (lambda (n)
	      (lambda (type values)
		(unless (der-object-identifier? type)
		  (springkussen-assertion-violation 'make-x509-attribute
						    "OID required" type))
		(unless (der-set? values)
		  (springkussen-assertion-violation 'make-x509-attribute
						    "Set required" values))
		((n x509-attribute->asn1-object) type values)))))
(define (x509-attribute->asn1-object self)
  (der-sequence (x509-attribute-type self) (x509-attribute-values self)))
(define (asn1-object->x509-attribute asn1-object)
  (unless (der-sequence? asn1-object)
    (springkussen-assertion-violation 'asn1-object->x509-attribute
				      "Invalid format" asn1-object))
  (let ((e (asn1-collection-elements asn1-object)))
    (unless (= (length e) 2)
      (springkussen-assertion-violation 'asn1-object->x509-attribute
					"Invalid format" asn1-object))
    (make-x509-attribute (car e) (cadr e))))

(define-record-type x509-attributes
  (parent <der-set>)
  (protocol (lambda (n)
	      (lambda (lis)
		(unless (for-all x509-attribute? lis)
		  (springkussen-assertion-violation 'make-x509-attributes
		    "X509 Attribute list is requires" lis))
		((n lis))))))
(define (asn1-object->x509-attributes asn1-object)
  (unless (der-set? asn1-object)
    (springkussen-assertion-violation 'asn1-object->x509-attributes
				      "Invalid format" asn1-object))
  (make-x509-attributes
   (map asn1-object->x509-attribute (asn1-collection-elements asn1-object))))

(define-record-type x509-certification-request-info
  (parent <asn1-encodable-object>)
  (fields version subject subject-pk-info attributes)
  (protocol (lambda (n)
	      (define (err msg irr)
		(springkussen-assertion-violation
		 'make-x509-certification-request-info msg irr))
	      (lambda (version subject subject-pk-info attributes)
		(unless (der-integer? version)
		  (err "Version must be a der integer" version))
		(unless (x509-name? subject)
		  (err "Subject must be a X509 name" subject))
		(unless (subject-public-key-info? subject-pk-info)
		  (err "SubjectPKInfo must be a SubjectPublicKeyInfo"
		       subject-pk-info))
		(unless (or (not attributes) (x509-attributes? attributes))
		  (err "Attributes must be a X509 attributes" attributes))
		((n x509-certification-request-info->asn1-object)
		 version subject subject-pk-info attributes)))))
(define (x509-certification-request-info->asn1-object cri)
  (let ((attr (x509-certification-request-info-attributes cri)))
    (apply der-sequence
	   (x509-certification-request-info-version cri)
	   (x509-certification-request-info-subject cri)
	   (x509-certification-request-info-subject-pk-info cri)
	   (if attr (list (make-der-tagged-object 0 #t attr)) '()))))

(define (asn1-object->x509-certification-request-info asn1-object)
  (define (get-attributes e)
    (and (not (null? e))
	 (let ((attr (car e)))
	   (unless (and (der-tagged-object? attr)
			(zero? (der-tagged-object-tag-no attr)))
	     (springkussen-assertion-violation
	      'asn1-object->x509-certification-request-info "Invalid format"
	      asn1-object))
	   attr)))
  (unless (der-sequence? asn1-object)
    (springkussen-assertion-violation
     'asn1-object->x509-certification-request-info "Invalid format"
     asn1-object))
  (let ((e (asn1-collection-elements asn1-object)))
    (when (< (length e) 3)
      (springkussen-assertion-violation
       'asn1-object->x509-certification-request-info "Invalid format"
       asn1-object))
    (let ((attr (get-attributes (cdddr e))))
      (make-x509-certification-request-info
       (car e)
       (asn1-object->x509-name (cadr e))
       (asn1-object->subject-public-key-info (caddr e))
       (and attr
	    (asn1-object->x509-attributes
	     (der-set (der-tagged-object-obj attr))))))))

(define-record-type x509-certification-request
  (parent <asn1-encodable-object>)
  (fields certification-request-info
	  signature-algorithm
	  signature)
  (protocol (lambda (n)
	      (define (err msg irr)
		(springkussen-assertion-violation
		 'make-x509-certification-request msg irr))
	      (lambda (cri signature-algorithm signature)
		(unless (x509-certification-request-info? cri)
		  (err "CertificationRequestInfo is required" cri))
		(unless (algorithm-identifier? signature-algorithm)
		  (err "AlgorithmIdentifier is required" signature-algorithm))
		(unless (der-bit-string? signature)
		  (err "Bit string is required" signature))
		((n x509-certification-request->asn1-object)
		 cri signature-algorithm signature)))))
(define (x509-certification-request->asn1-object self)
  (der-sequence
   (x509-certification-request-certification-request-info self)
   (x509-certification-request-signature-algorithm self)
   (x509-certification-request-signature self)))
(define (asn1-object->x509-certification-request asn1-object)
  (unless (der-sequence? asn1-object)
    (springkussen-assertion-violation 'asn1-object->x509-certification-request
				      "Invalid format" asn1-object))
  (let ((e (asn1-collection-elements asn1-object)))
    (unless (= (length e) 3)
      (springkussen-assertion-violation 'asn1-object->x509-certification-request
					"Invalid format" asn1-object))
    (make-x509-certification-request
     (asn1-object->x509-certification-request-info (car e))
     (asn1-object->algorithm-identifier (cadr e))
     (caddr e))))

(define-record-type x509-certificate-signing-request
  (parent <asn1-encodable-object>)
  (fields cr sequence)
  (protocol (lambda (n)
	      (define (check cr)
		(unless (x509-certification-request? cr)
		  (springkussen-assertion-violation
		   'make-x509-certificate-signing-request 
		   "X509 certification request is required" cr)))
	      (case-lambda
	       ((cr)
		(check cr)
		((n x509-certificate-signing-request-sequence)
		 cr (x509-certification-request->asn1-object cr)))
	       ((cr sequence)
		(check cr)
		((n x509-certificate-signing-request-sequence)
		 cr sequence))))))

(define (asn1-object->x509-certificate-signing-request asn1-object)
  (let ((cr (asn1-object->x509-certification-request asn1-object)))
    (make-x509-certificate-signing-request cr asn1-object)))
		 
(define read-x509-certificate-signing-request
  (case-lambda
   (() (read-x509-certificate-signing-request (current-input-port)))
   ((in)
    (asn1-object->x509-certificate-signing-request (read-asn1-object in)))))

(define (bytevector->x509-certificate-signing-request bv)
  (read-x509-certificate-signing-request (open-bytevector-input-port bv)))


(define (x509-certificate-signing-request:subject csr)
  (define cr (x509-certificate-signing-request-cr csr))
  (define cri (x509-certification-request-certification-request-info cr))
  (x509-name->list (x509-certification-request-info-subject cri)))

(define (x509-certificate-signing-request:subject-pk-info csr)
  (define cr (x509-certificate-signing-request-cr csr))
  (define cri (x509-certification-request-certification-request-info cr))
  (x509-certification-request-info-subject-pk-info cri))

;; serial-number and validity must be provided externally
(define x509-certificate-signing-request:sign
  (case-lambda
   ((csr sn validity ca-cert private-key)
    (x509-certificate-signing-request:sign
     csr sn validity ca-cert private-key #f))
   ((csr sn validity ca-cert private-key extensions)
    (sign-csr csr sn validity ca-cert private-key extensions))))

(define digest-parameter (make-signature-digest-parameter *digest:sha256*))
(define rsa-signer-parameter
  (make-signature-parameter digest-parameter
   ;; Should we use PSS?
   (make-rsa-signature-encode-parameter pkcs1-emsa-v1.5-encode)))
(define ecdsa-signer-parameter
  (make-signature-parameter digest-parameter
    (make-ecdsa-encode-parameter (ecdsa-signature-encode-type der))))
(define (sign-csr csr sn validity ca-cert private-key extensions)
  (define signature
    (make-algorithm-identifier
     (make-der-object-identifier
      (cond ((rsa-private-key? private-key) "1.2.840.113549.1.1.11")
	    ((ecdsa-private-key? private-key) "1.2.840.10045.4.3.2")
	    (else
	     (springkussen-assertion-violation 'sign-csr
					       "Unknown private key type"))))
     (make-der-null)))
  (define (get-signer private-key)
    (cond ((rsa-private-key? private-key)
	   (make-signer *signer:rsa* private-key rsa-signer-parameter))
	  ((ecdsa-private-key? private-key)
	   (make-signer *signer:ecdsa* private-key ecdsa-signer-parameter))
	  (else
	   (springkussen-assertion-violation 'sign-csr
					     "Unknown private key type"))))
  (define (csr->tbs csr sn validity ca-cert extensions)
    (define version (and extensions (make-der-integer 2)))
    (make-x509-tbs-certificate
     #f
     version
     (make-der-integer sn)
     signature
     (list->x509-name (x509-certificate:issuer ca-cert))
     validity
     (list->x509-name (x509-certificate-signing-request:subject csr))
     (x509-certificate-signing-request:subject-pk-info csr)
     #f
     #f
     extensions))

  (let* ((tbs (csr->tbs csr sn validity ca-cert extensions))
	 (signing-content (asn1-object->bytevector tbs))
	 (sig (signer:sign-message (get-signer private-key) signing-content)))
    (make-x509-certificate
     (make-x509-certificate-structure
      tbs signature (make-der-bit-string sig) #f))))

)
