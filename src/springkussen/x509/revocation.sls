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

;; ref: https://datatracker.ietf.org/doc/html/rfc5280
#!r6rs
(library (springkussen x509 revocation)
    (export x509-certificate-revocation-list?
	    make-x509-certificate-revocation-list
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

	    x509-tbs-cert-list? make-x509-tbs-cert-list
	    x509-revoked-certificate? make-x509-revoked-certificate
	    x509-certificate-list? make-x509-certificate-list)
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen conditions)
	    (springkussen misc lambda)
	    (springkussen signature)
	    (springkussen x509 types)
	    (springkussen x509 certificate)
	    (springkussen x509 extensions)
	    (springkussen x509 signature))

;; TBSCertList  ::=  SEQUENCE  {
;;      version                 Version OPTIONAL,
;;                                   -- if present, MUST be v2
;;      signature               AlgorithmIdentifier,
;;      issuer                  Name,
;;      thisUpdate              Time,
;;      nextUpdate              Time OPTIONAL,
;;      revokedCertificates     SEQUENCE OF SEQUENCE  {
;;           userCertificate         CertificateSerialNumber,
;;           revocationDate          Time,
;;           crlEntryExtensions      Extensions OPTIONAL
;;                                    -- if present, version MUST be v2
;;                                }  OPTIONAL,
;;      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
;;                                    -- if present, version MUST be v2
;;                                }
(define-record-type x509-revoked-certificate
  (parent <asn1-encodable-object>)
  (fields user-certificate
	  revocation-date
	  crl-entry-extensions)
  (protocol (lambda (n)
	      (lambda/typed ((user-certificate der-integer?)
			     (revocation-date x509-time?)
			     (crl-entry-extensions (or #f x509-extensions?)))
		((n x509-revoked-certificate->asn1-object)
		 user-certificate revocation-date crl-entry-extensions)))))
(define (x509-revoked-certificate->asn1-object self)
  (make-der-sequence
   (filter values (list (x509-revoked-certificate-user-certificate self)
			(x509-revoked-certificate-revocation-date self)
			(x509-revoked-certificate-crl-entry-extensions self)))))

(define (asn1-object->x509-revoked-certificate asn1-object)
  (define (err)
    (springkussen-assertion-violation 'asn1-object->x509-revoked-certificate
				      "Invalid format" asn1-object))
  (unless (der-sequence? asn1-object) (err))
  (let ((e (asn1-collection-elements asn1-object)))
    (when (< (length e) 2) (err))
    (let ((uc (car e))
	  (rd (make-x509-time (cadr e)))
	  (cee (and (not (null? (cddr e)))
		    (asn1-object->x509-extensions (caddr e)))))
      (make-x509-revoked-certificate uc rd cee))))

(define-record-type x509-tbs-cert-list
  (parent <asn1-encodable-object>)
  (fields version
	  signature
	  issuer
	  this-update
	  next-update
	  revoked-certificates
	  crl-extensions)
  (protocol (lambda (n)
	      (define (version2? v)
		(and (der-integer? v) (= 1 (der-integer-value v))))
	      (define revoked-certificates?
		(der-sequence-of? x509-revoked-certificate?))
	      (lambda/typed ((version (or #f version2?))
			     (signature (or #f algorithm-identifier?))
			     (issuer x509-name?)
			     (this-update x509-time?)
			     (next-update (or #f x509-time?))
			     (revoked-certificates
			      (or #f revoked-certificates?))
			     (crl-extensions (or #f x509-extensions?)))
		((n x509-tbs-cert-list->asn1-object)
		 version signature issuer this-update next-update
		 revoked-certificates crl-extensions)))))
(define (x509-tbs-cert-list->asn1-object self)
  (make-der-sequence
   (filter values (list (x509-tbs-cert-list-version self)
			(x509-tbs-cert-list-signature self)
			(x509-tbs-cert-list-issuer self)
			(x509-tbs-cert-list-this-update self)
			(x509-tbs-cert-list-next-update self)
			(x509-tbs-cert-list-revoked-certificates self)
			(cond ((x509-tbs-cert-list-crl-extensions self) =>
			       (lambda (c) (make-der-tagged-object 0 #t c)))
			      (else #f))))))

(define (asn1-object->x509-tbs-cert-list asn1-object)
  (define (err)
    (springkussen-assertion-violation 'asn1-object->x509-tbs-cert-list
				      "Invalid format" asn1-object))
  (define (parse-optionals e*)
    (when (> (length e*) 3) (err))
    (let loop ((next #f) (rc #f) (ext* #f) (e* e*))
      (if (null? e*)
	  (values next rc ext*)
	  (let ((e (car e*)))
	    (cond ((or (der-utc-time? e) (der-generalized-time? e))
		   (when (or next rc ext*) (err))
		   (loop (make-x509-time e) rc ext* (cdr e*)))
		  ((and (der-tagged-object? e)
			(= (der-tagged-object-tag-no e) 0))
		   (when ext* (err))
		   (let ((obj (der-tagged-object-obj e)))
		     (loop next rc (asn1-object->x509-extensions obj)
			   (cdr e*))))
		  ((der-sequence? e)
		   (when (or rc ext*) (err))
		   (let ((rc (make-der-sequence
			      (map asn1-object->x509-revoked-certificate
				   (asn1-collection-elements e)))))
		     (loop next rc ext* (cdr e*))))
		  (else (err)))))))
    
  (unless (der-sequence? asn1-object) (err))
  (let ((e (asn1-collection-elements asn1-object)))
    (when (< (length e) 3) (err))
    (let-values (((version e*)  (if (der-integer? (car e))
				    (values (car e) (cdr e))
				    (values #f e))))
      (let ((sig (asn1-object->algorithm-identifier (car e*)))
	    (issuer (asn1-object->x509-name (cadr e*)))
	    (this (make-x509-time (caddr e*))))
	(let-values (((next rc ext*) (parse-optionals (cdddr e*))))
	  (make-x509-tbs-cert-list version sig issuer this next rc ext*))))))

;; CertificateList  ::=  SEQUENCE  {
;;      tbsCertList          TBSCertList,
;;      signatureAlgorithm   AlgorithmIdentifier,
;;      signatureValue       BIT STRING  }
(define-record-type x509-certificate-list
  (parent <asn1-encodable-object>)
  (fields tbs-cert-list
	  signature-algorithm ;; optional for unsigned
	  signature-value)    ;; optional for unsigned
  (protocol (lambda (n)
	      (lambda/typed ((tbs-cert-list x509-tbs-cert-list?)
			     (signature-algorithm (or #f algorithm-identifier?))
			     (signature (or #f der-bit-string?)))
		((n x509-certificate-list->asn1-object)
		 tbs-cert-list signature-algorithm signature)))))
(define (x509-certificate-list->asn1-object self)
  (let ((sa (x509-certificate-list-signature-algorithm self))
	(sig (x509-certificate-list-signature-value self)))
    (unless (and sa sig)
      (springkussen-assertion-violation 'x509-certificate-list->asn1-object
					"CertificateList is not signed"))
    (der-sequence (x509-certificate-list-tbs-cert-list self) sa sig)))

(define (asn1-object->x509-certificate-list asn1-object)
  (unless (der-sequence? asn1-object)
    (springkussen-assertion-violation 'asn1-object->x509-certificate-list
				      "Invalid format" asn1-object))
  (let ((e (asn1-collection-elements asn1-object)))
    (unless (der-bit-string? (caddr e))
      (springkussen-assertion-violation 'asn1-object->x509-certificate-list
					"Invalid format" asn1-object))
    (make-x509-certificate-list
     (asn1-object->x509-tbs-cert-list (car e))
     (asn1-object->algorithm-identifier (cadr e))
     (caddr e))))

(define-record-type x509-certificate-revocation-list
  (parent <asn1-encodable-object>)
  (fields sequence ;; original object if provided
	  cl)
  (protocol (lambda (n)
	      (case-lambda/typed
	       (((cl x509-certificate-list?))
		((n x509-certificate-revocation-list-sequence)
		 (x509-certificate-list->asn1-object cl) cl))
	       (((sequence der-sequence?)
		 (cl x509-certificate-list?))
		((n x509-certificate-revocation-list-sequence) sequence cl))))))

(define (asn1-object->x509-certificate-revocation-list asn1-object)
  (make-x509-certificate-revocation-list asn1-object
    (asn1-object->x509-certificate-list asn1-object)))

(define read-x509-certificate-revocation-list
  (case-lambda
   (() (read-x509-certificate-revocation-list (current-input-port)))
   ((in)
    (asn1-object->x509-certificate-revocation-list (read-asn1-object in)))))
(define (bytevector->x509-certificate-revocation-list bv)
  (read-x509-certificate-revocation-list (open-bytevector-input-port bv)))

(define write-x509-certificate-revocation-list
  (case-lambda
   ((crl) (write-x509-certificate-revocation-list crl (current-output-port)))
   ((crl out) (write-asn1-object crl out))))
(define (x509-certificate-revocation-list->bytevector crl)
  (asn1-object->bytevector crl))

(define/typed (x509-certificate-revocation-list:issuer
	       (crl x509-certificate-revocation-list?))
  (define cl (x509-certificate-revocation-list-cl crl))
  (define tbs (x509-certificate-list-tbs-cert-list cl))
  (x509-name->list (x509-tbs-cert-list-issuer tbs)))

(define/typed (x509-certificate-revocation-list:revoked-certificates
	       (crl x509-certificate-revocation-list?))
  (define cl (x509-certificate-revocation-list-cl crl))
  (define tbs (x509-certificate-list-tbs-cert-list cl))
  (define (->list rc)
    (list (der-integer-value (x509-revoked-certificate-user-certificate rc))
	  (x509-time:date-value (x509-revoked-certificate-revocation-date rc))))
  (map ->list
       (asn1-collection-elements
	(x509-tbs-cert-list-revoked-certificates tbs))))

(define/typed (x509-certificate-revocation-list:certificate-revoked?
	       (crl x509-certificate-revocation-list?)
	       (cert x509-certificate?))
  (define cert-issuer (x509-certificate:issuer cert))
  (define cert-sn (x509-certificate:serial-number cert))
  (define issuer (x509-certificate-revocation-list:issuer crl))
  ;; if the issuers are not the same, we don't know if the certificate is
  ;; revoked or not, so just return #t
  (or (not (equal? cert-issuer issuer))
      (assv cert-sn
	    (x509-certificate-revocation-list:revoked-certificates crl))))

(define/typed (x509-certificate-revocation-list:signed?
	       (crl x509-certificate-revocation-list?))
  (define cl (x509-certificate-revocation-list-cl crl))
  (and (x509-certificate-list-signature-algorithm cl)
       (x509-certificate-list-signature-value cl)))

;; creates a new CRL with signature if the given crl is not signed
(define/typed (x509-certificate-revocation-list:sign
	       (crl x509-certificate-revocation-list?)
	       (private-key private-key?))
  (if (x509-certificate-revocation-list:signed? crl)
      crl
      (let* ((cl (x509-certificate-revocation-list-cl crl))
	     (tbs-list (x509-certificate-list-tbs-cert-list cl))
	     (sign-sa (make-x509-default-signature-algorithm private-key))
	     (signer
	      ((signature-algorithm->signer-creator sign-sa) private-key))
	     (sig (signer:sign-message signer
				       (asn1-object->bytevector tbs-list))))
	(make-x509-certificate-revocation-list
	 (make-x509-certificate-list
	  (make-x509-tbs-cert-list
	   (x509-tbs-cert-list-version tbs-list)
	   sign-sa
	   (x509-tbs-cert-list-issuer tbs-list)
	   (x509-tbs-cert-list-this-update tbs-list)
	   (x509-tbs-cert-list-next-update tbs-list)
	   (x509-tbs-cert-list-revoked-certificates tbs-list)
	   (x509-tbs-cert-list-crl-extensions tbs-list))
	  sign-sa
	  (make-der-bit-string sig))))))

(define/typed (x509-certificate-revocation-list:add-revoked-certificates
	       (crl x509-certificate-revocation-list?)
	       (revoked-certificates (list-of? x509-revoked-certificate?)))
  (let* ((cl (x509-certificate-revocation-list-cl crl))
	 (tbs-list (x509-certificate-list-tbs-cert-list cl)))
    (make-x509-certificate-revocation-list
     (make-x509-certificate-list
      (make-x509-tbs-cert-list
       (x509-tbs-cert-list-version tbs-list)
       #f
       (x509-tbs-cert-list-issuer tbs-list)
       (x509-tbs-cert-list-this-update tbs-list)
       (x509-tbs-cert-list-next-update tbs-list)
       (make-der-sequence
	(append (asn1-collection-elements
		 (x509-tbs-cert-list-revoked-certificates tbs-list))
		revoked-certificates))
       (x509-tbs-cert-list-crl-extensions tbs-list))
      #f #f))))
  
)
