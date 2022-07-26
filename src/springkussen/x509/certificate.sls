;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/x509/certificate.sls - X.509 certificate
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

;; ref: https://datatracker.ietf.org/doc/html/rfc5280
#!r6rs
(library (springkussen x509 certificate)
    (export make-x509-certificate x509-certificate?
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

	    make-x509-tbs-certificate x509-tbs-certificate
	    tbs-certificate->asn1-object
	    asn1-object->x509-tbs-certificate

	    make-x509-certificate-structure x509-certificate-structure?
	    x509-certificate-structure->asn1-object
	    asn1-object->x509-certificate-structure
	    
	    make-x509-validity x509-validity?
	    x509-validity-not-before x509-validity-not-after
	    validity->asn1-object
	    asn1-object->x509-validity)
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen conditions)
	    (springkussen digest)
	    (springkussen signature)
	    (springkussen x509 types))

(define-record-type x509-validity
  (parent <asn1-encodable-object>)
  (fields not-before not-after)
  (protocol (lambda (n)
	      (lambda (not-before not-after)
		(unless (and (x509-time? not-before) (x509-time? not-after))
		  (springkussen-assertion-violation 'make-x509-validity
						    "X509 time required"
						    not-before not-after))
		((n validity->asn1-object) not-before not-after)))))
(define (validity->asn1-object self)
  (der-sequence (x509-validity-not-before self)
		(x509-validity-not-after self)))
(define (asn1-object->x509-validity asn1-object)
  (unless (der-sequence asn1-object)
    (springkussen-assertion-violation 'asn1-object->x509-validity
				      "Invalid format" asn1-object))
  (let ((e (asn1-collection-elements asn1-object)))
    (unless (= (length e) 2)
      (springkussen-assertion-violation 'asn1-object->x509-validity
					"Invalid format" asn1-object))
    (make-x509-validity (make-x509-time (car e))
			(make-x509-time (cadr e)))))

  
;; TBSCertificate  ::=  SEQUENCE  {
;;         version         [0]  EXPLICIT Version DEFAULT v1,
;;         serialNumber         CertificateSerialNumber,
;;         signature            AlgorithmIdentifier,
;;         issuer               Name,
;;         validity             Validity,
;;         subject              Name,
;;         subjectPublicKeyInfo SubjectPublicKeyInfo,
;;         issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
;;                              -- If present, version MUST be v2 or v3
;;         subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
;;                              -- If present, version MUST be v2 or v3
;;         extensions      [3]  EXPLICIT Extensions OPTIONAL
;;                              -- If present, version MUST be v3
;;         }
(define-record-type x509-tbs-certificate
  (parent <asn1-encodable-object>)
  (fields sequence ;; original object if provided
	  version
	  serial-number
	  signature
	  issuer
	  validity
	  subject
	  subject-public-key-info
	  issuer-unique-id
	  subject-unique-id
	  extensions)
  (protocol (lambda (n)
	      (define (err v)
		(springkussen-assertion-violation 'make-x509-tbs-certificate
						  "Invalid value" v))
	      (define make-tbs-cert
		(case-lambda
		 ((sequence version serial-number signature issuer
			    validity subject subject-public-key-info
			    issuer-unique-id
			    subject-unique-id extensions)
		  (unless (or (not version) (der-integer? version))
		    (err version))
		  (unless (der-integer? serial-number) (err serial-number))
		  (unless (algorithm-identifier? signature) (err signature))
		  (unless (x509-name? issuer) (err issuer))
		  (unless (x509-validity? validity) (err validity))
		  (unless (x509-name? subject) (err subject))
		  (unless (subject-public-key-info? subject-public-key-info)
		    (err subject-public-key-info))
		  (unless (or (not issuer-unique-id)
			      (der-bit-string? issuer-unique-id))
		    (err issuer-unique-id))
		  (unless (or (not subject-unique-id)
			      (der-bit-string? subject-unique-id))
		    (err subject-unique-id))
		  (unless (or (not extensions)
			      (x509-extensions? extensions))
		    (err extensions))
		  ((n tbs-certificate->asn1-object)
		   sequence version serial-number signature
		   issuer validity subject subject-public-key-info
		   issuer-unique-id subject-unique-id extensions))))
	      make-tbs-cert)))
(define (tbs-certificate->asn1-object self)
  (define (->tag-object tag-no obj explicit?)
    (and obj (make-der-tagged-object tag-no explicit? obj)))
  (or (x509-tbs-certificate-sequence self)
      (make-der-sequence
       (filter values
	(list
	 (->tag-object 0 (x509-tbs-certificate-version self) #t)
	 (x509-tbs-certificate-serial-number self)
	 (x509-tbs-certificate-signature self)
	 (x509-tbs-certificate-issuer self)
	 (x509-tbs-certificate-validity self)
	 (x509-tbs-certificate-subject self)
	 (x509-tbs-certificate-subject-public-key-info self)
	 (->tag-object 1 (x509-tbs-certificate-issuer-unique-id self) #f)
	 (->tag-object 2 (x509-tbs-certificate-subject-unique-id self) #f)
	 (->tag-object 3 (x509-tbs-certificate-extensions self) #t))))))
(define (asn1-object->x509-tbs-certificate asn1-object)
  (define (find-tag e tag)
    (define (tag-of tag)
      (lambda (e)
	(and (der-tagged-object? e)
	     (= (der-tagged-object-tag-no e) tag)
	     e)))
    (exists (tag-of tag) e))
  (define (ensure-bit-string d)
    (cond ((der-bit-string? d) d)
	  ((der-octet-string? d)
	   (make-der-bit-string (der-octet-string-value d)))
	  ;; let the constructor throw an error
	  (else d)))
  (unless (der-sequence? asn1-object)
    (springkussen-assertion-violation 'asn1-object->x509-tbs-certificate
				      "DER Sequence required" asn1-object))
  (let ((e (asn1-collection-elements asn1-object)))
    ;; 4 of the fields are optional (incl. version)
    (when (< (length e) 6)
      (springkussen-assertion-violation 'asn1-object->x509-tbs-certificate
					"Invalid X509 certificate format"
					asn1-object))
    (let* ((e* (if (der-tagged-object? (car e)) (cdr e) e))
	   (serial-number (car e*))
	   (signature (cadr e*))
	   (issuer (caddr e*))
	   (validity (cadddr e*))
	   (subject (car (cddddr e*)))
	   (spki (cadr (cddddr e*)))
	   (version (find-tag e 0))
	   (issuer-unique-id (find-tag e 1))
	   (subject-unique-id (find-tag e 2))
	   (extensions (find-tag e 3)))
      (make-x509-tbs-certificate
       asn1-object
       (and version (der-tagged-object-obj version))
       serial-number
       (asn1-object->algorithm-identifier signature)
       (asn1-object->x509-name issuer)
       (asn1-object->x509-validity validity)
       (asn1-object->x509-name subject)
       (asn1-object->subject-public-key-info spki)
       (and issuer-unique-id
	    (ensure-bit-string (der-tagged-object-obj issuer-unique-id)))
       (and subject-unique-id
	    (ensure-bit-string (der-tagged-object-obj subject-unique-id)))
       (and extensions
	    (asn1-object->x509-extensions
	     (der-tagged-object-obj extensions)))))))
			       

;; Certificate  ::=  SEQUENCE  {
;;      tbsCertificate       TBSCertificate,
;;      signatureAlgorithm   AlgorithmIdentifier,
;;      signatureValue       BIT STRING  }
;; a bit of sad naming
(define-record-type x509-certificate-structure
  (parent <asn1-encodable-object>)
  (fields tbs-certificate
	  signature-algorithm
	  signature
	  sequence)
  (protocol (lambda (n)
	      (lambda (tbs-certificate signature-algorithm signature sequence)
		(unless (x509-tbs-certificate? tbs-certificate)
		  (springkussen-assertion-violation 'make-x509-certificate
		    "TBS Certificate required" tbs-certificate))
		(unless (algorithm-identifier? signature-algorithm)
		  (springkussen-assertion-violation 'make-x509-certificate
		    "Invalid signature algorithm" signature-algorithm))
		(unless (der-bit-string? signature)
		  (springkussen-assertion-violation 'make-x509-certificate
		    "Invalid signature" signature))
		;; TODO make algorithm identifier somewhere...
		((n x509-certificate-structure->asn1-object)
		 tbs-certificate signature-algorithm signature sequence)))))
(define (x509-certificate-structure->asn1-object self)
  (or (x509-certificate-structure-sequence self)
      (der-sequence
       (x509-certificate-structure-tbs-certificate self)
       (x509-certificate-structure-signature-algorithm self)
       (x509-certificate-structure-signature self))))

(define (asn1-object->x509-certificate-structure asn1-object)
  (unless (der-sequence? asn1-object)
    (springkussen-assertion-violation 'asn1-object->x509-certificate-structure
				      "DER Sequence required" asn1-object))
  (let ((e (asn1-collection-elements asn1-object)))
    (unless (= (length e) 3)
      (springkussen-assertion-violation 'asn1-object->x509-certificate-structure
					"Invalid X509 certificate format"
					asn1-object))
    (unless (der-bit-string? (caddr e))
      (springkussen-assertion-violation 'asn1-object->x509-certificate-structure
					"Invalid X509 certificate format"
					asn1-object))
    (make-x509-certificate-structure
     (asn1-object->x509-tbs-certificate (car e))
     (asn1-object->algorithm-identifier (cadr e))
     (caddr e)
     asn1-object)))

(define-record-type x509-certificate
  (parent <asn1-encodable-object>)
  (fields c
	  sequence)
  (protocol (lambda (n)
	      (define (check c)
		(unless (x509-certificate-structure? c)
		  (springkussen-assertion-violation 'make-x509-certificate
		    "X509 certificate structure is required" c)))
	      (case-lambda
	       ((c)
		(check c)
		((n x509-certificate-sequence) c
		 (x509-certificate-structure->asn1-object c)))
	       ((c sequence)
		(check c)
		((n x509-certificate-sequence) c sequence))))))
(define (asn1-object->x509-certificate asn1-object)
  (let ((cs (asn1-object->x509-certificate-structure asn1-object)))
    (make-x509-certificate cs asn1-object)))

(define read-x509-certificate
  (case-lambda
   (() (read-x509-certificate (current-input-port)))
   ((in) (asn1-object->x509-certificate (read-asn1-object in)))))

(define (bytevector->x509-certificate bv)
  (read-x509-certificate (open-bytevector-input-port bv)))

(define write-x509-certificate
  (case-lambda
   ((cert) (write-x509-certificate cert (current-output-port)))
   ((cert out) (write-asn1-object cert out))))

(define (x509-certificate->bytevector cert)
  (let-values (((out e) (open-bytevector-output-port)))
    (write-x509-certificate cert out)
    (e)))

(define (x509-certificate:public-key cert)
  (define c (x509-certificate-c cert))
  (define tbs (x509-certificate-structure-tbs-certificate c))
  (define spki (x509-tbs-certificate-subject-public-key-info tbs))
  (subject-public-key-info->public-key spki))

(define (x509-certificate:version cert)
  (define c (x509-certificate-c cert))
  (define tbs (x509-certificate-structure-tbs-certificate c))
  (define v (x509-tbs-certificate-version tbs))
  (or (and v (+ (der-integer-value v)) 1) 1))

(define (x509-certificate:serial-number cert)
  (define c (x509-certificate-c cert))
  (define tbs (x509-certificate-structure-tbs-certificate c))
  (define v (x509-tbs-certificate-serial-number tbs))
  (der-integer-value v))

(define (x509-certificate:signature cert)
  (define c (x509-certificate-c cert))
  (der-bit-string-value (x509-certificate-structure-signature c)))

(define (x509-certificate:signature-algorithm cert)
  (define c (x509-certificate-c cert))
  (x509-certificate-structure-signature-algorithm c))

(define (x509-certificate:issuer cert)
  (define c (x509-certificate-c cert))
  (define tbs (x509-certificate-structure-tbs-certificate c))
  (x509-name->list (x509-tbs-certificate-issuer tbs)))

(define (x509-certificate:validity cert)
  (define c (x509-certificate-c cert))
  (define tbs (x509-certificate-structure-tbs-certificate c))
  (x509-tbs-certificate-validity tbs))

(define (x509-certificate:subject cert)
  (define c (x509-certificate-c cert))
  (define tbs (x509-certificate-structure-tbs-certificate c))
  (x509-name->list (x509-tbs-certificate-subject tbs)))

(define (x509-certificate:issuer-unique-id cert)
  (define c (x509-certificate-c cert))
  (define tbs (x509-certificate-structure-tbs-certificate c))
  ;; TODO how should we provide?
  (x509-tbs-certificate-issuer-unique-id tbs))

(define (x509-certificate:subject-unique-id cert)
  (define c (x509-certificate-c cert))
  (define tbs (x509-certificate-structure-tbs-certificate c))
  ;; TODO how should we provide?
  (x509-tbs-certificate-subject-unique-id tbs))

(define (x509-certificate:extensions cert)
  (define c (x509-certificate-c cert))
  (define tbs (x509-certificate-structure-tbs-certificate c))
  (x509-tbs-certificate-extensions tbs))

;; Validate certificate
(define (x509-certificate:validate cert validators)
  (unless (for-all (lambda (v) (v cert)) validators)
    (springkussen-assertion-violation 'x509-certificate:validate
				      "Failed to validate certificate" cert))
  #t)

;; TODO maybe somewhere else
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

(define (make-x509-signature-validator ca-cert)
  (define public-key (x509-certificate:public-key ca-cert))
  (lambda (cert)
    (define c (x509-certificate-c cert))
    (define signature-algorithm
      (x509-certificate-structure-signature-algorithm c))
    (define signature (x509-certificate-structure-signature c))
    (define oid (algorithm-identifier-algorithm signature-algorithm))
    (define message (asn1-object->bytevector
		     (or (and (x509-certificate-structure-sequence c)
			      (car (asn1-collection-elements
				    (x509-certificate-structure-sequence c))))
			 (x509-certificate-structure-tbs-certificate c))))
    
    (cond ((assoc (der-object-identifier-value oid) *oid-verifier-parameter*) =>
	   (lambda (slot)
	     (define desc (cadr slot))
	     (define param (caddr slot))
	     (let ((verifier (make-verifier desc public-key param)))
	       (verifier:verify-signature verifier message
					  (der-bit-string-value signature)))))
	  (else
	   (springkussen-error 'signature-validator
			       "Unknown signature OID"
			       (der-object-identifier-value oid))))))
)
