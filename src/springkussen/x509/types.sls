;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/x509/types.sls - X.509 certificate types
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
(library (springkussen x509 types)
    (export make-algorithm-identifier algorithm-identifier?
	    algorithm-identifier-algorithm algorithm-identifier-parameters
	    asn1-object->algorithm-identifier ;; useful?

	    make-subject-public-key-info subject-public-key-info?
	    asn1-object->subject-public-key-info ;; useful?
	    subject-public-key-info->public-key
	    bytevector->subject-public-key-info
	    public-key->subject-public-key-info
	    
	    make-rdn rdn? rdn-values

	    make-x509-name x509-name?
	    x509-name->asn1-object asn1-object->x509-name
	    x509-name->list list->x509-name
	    asn1-object->x509-name
	    x509-name->string

	    make-x509-time x509-time? x509-time-value
	    x509-time:date-value
	    
	    make-x509-extension x509-extension?
	    (rename (x509-extension <x509-extension>))
	    x509-extension-id x509-extension-critical? x509-extension-value
	    x509-extension->asn1-object asn1-object->x509-extension

	    make-x509-extensions x509-extensions?
	    (rename (asn1-collection-elements x509-extensions-values))
	    asn1-object->x509-extensions)
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen conditions)
	    (springkussen signature))

(define-record-type rdn
  (parent <asn1-encodable-object>)
  (fields values)
  (protocol (lambda (n)
	      (define (attribute-type-and-value? o)
		(and (der-sequence? o)
		     (let ((e (asn1-collection-elements o)))
		       (and (= (length e) 2)
			    (der-object-identifier? (car e))))))
			    
	      (lambda (values)
		(unless (der-set? values)
		  (springkussen-assertion-violation 'make-rdn
						    "DER set required" values))
		(let ((e (asn1-collection-elements values)))
		  (unless (for-all attribute-type-and-value? e)
		    (springkussen-assertion-violation 'make-rdn
		      "Set elements must be AttributeTypeAndValue" values))
		  ((n rdn->asn1-object) e))))))
(define (rdn->asn1-object self) (make-der-set (rdn-values self)))

(define *default-symbols*
  '(("2.5.4.3"                    . CN)
    ("2.5.4.4"                    . SURNAME)
    ("2.5.4.5"                    . SERIALNUMER)
    ("2.5.4.6"                    . C)
    ("2.5.4.7"                    . L)
    ("2.5.4.8"                    . ST)
    ("2.5.4.9"                    . STREET)
    ("2.5.4.10"                   . O)
    ("2.5.4.11"                   . OU)
    ("2.5.4.12"                   . T)
    ("2.5.4.26"                   . DN)
    ("2.5.4.42"                   . GIVENNAME)
    ("2.5.4.44"                   . GENERATION)
    ("1.2.840.113549.1.9.1"       . E)
    ("0.9.2342.19200300.100.1.25" . DC)
    ("0.9.2342.19200300.100.1.1"  . UID)))
(define (rdn->list rdn)
  (define (->list av*)
    ;; RDN can have multiple components for historical reason and it's
    ;; strongly discouraged to use it. though, we may face some of the
    ;; old format, so follow the specification...
    (define (->pair av)
      (let* ((oid (der-object-identifier-value (car av)))
	     (dv (cadr av))
	     (v (if (asn1-simple-object? dv)
		    (asn1-simple-object-value dv)
		    dv)))
	(cond ((assoc oid *default-symbols*) =>
	       (lambda (slot) (list (cdr slot) v)))
	      (else (list oid v)))))
    (->pair (asn1-collection-elements av*)))
  (unless (rdn? rdn)
    (springkussen-assertion-violation 'rdn->list "RDN is required" rdn))
  (apply append (map ->list (rdn-values rdn))))

(define-record-type x509-name
  (parent <asn1-encodable-object>)
  (fields rdns)
  (protocol (lambda (n)
	      (lambda (rdns)
		(unless (for-all rdn? rdns)
		  (springkussen-assertion-violation 'make-x509-name
		   "RDNSequence required" rdns))
		((n x509-name->asn1-object) rdns)))))
(define (x509-name->asn1-object self)
  (make-der-sequence (x509-name-rdns self)))
(define (asn1-object->x509-name asn1-object)
  (unless (der-sequence? asn1-object)
    (springkussen-assertion-violation 'asn1-object->x509-name
				      "Invalid format" asn1-object))
  (make-x509-name (map make-rdn (asn1-collection-elements asn1-object))))

(define (x509-name->list x509-name)
  (unless (x509-name? x509-name)
    (springkussen-assertion-violation 'x509-name->list
				      "X509 name is required" x509-name))
  (map rdn->list (x509-name-rdns x509-name)))

(define (list->x509-name lis)
  (define (->rdn e)
    (define v (let ((v (cadr e)))
		(cond ((string? v) (make-der-printable-string v))
		      ((asn1-object? v) v)
		      (else
		       (springkussen-assertion-violation 'list->x509-name
			 "Invalid argument" e lis)))))
    (define (pred slot) (eq? (car e) (cdr slot)))
    (let ((oid (cond ((find pred *default-symbols*) => car)
		     (else (car e)))))
      (der-set (der-sequence (make-der-object-identifier oid) v))))
  (make-x509-name (map make-rdn (map ->rdn lis))))

(define (x509-name->string x509-name)
  (let-values (((out e) (open-string-output-port)))
    (do ((lis (x509-name->list x509-name) (cdr lis)) (first? #t #f))
	((null? lis) (e))
      (let* ((e (car lis))
	     (a (car e))
	     (v (cadr e)))
	(unless first? (put-string out ", "))
	(put-datum out a) (put-char out #\=) (put-datum out v)))))

(define-record-type x509-time
  (parent <asn1-encodable-object>)
  (fields value)
  (protocol (lambda (n)
	      (lambda (time)
		(unless (or (der-utc-time? time) (der-generalized-time? time))
		  (springkussen-assertion-violation 'make-x509-time
		    "UTC or generalized time required" time))
		((n x509-time-value) time)))))
(define (x509-time:date-value time)
  (asn1-simple-object-value (x509-time-value time)))

(define-record-type x509-extension
  (parent <asn1-encodable-object>)
  (fields id critical? value)
  (protocol (lambda (n)
	      (case-lambda
	       ((id value)
		((n x509-extension->asn1-object) id #f value))
	       ((id critical? value)
		((n x509-extension->asn1-object) id critical? value))))))
(define (x509-extension->asn1-object self)
  (der-sequence
   (x509-extension-id self)
   (make-der-boolean (x509-extension-critical? self))
   (x509-extension-value self)))
(define (asn1-object->x509-extension asn1-object)
  (unless (der-sequence? asn1-object)
    (springkussen-assertion-violation asn1-object->x509-extension
				      "Invalid format" asn1-object))
  (let ((e (asn1-collection-elements asn1-object)))
    (unless (<= 2 (length e) 3)
      (springkussen-assertion-violation asn1-object->x509-extension
					"Invalid format" asn1-object))
    (let* ((len (length e))
	   (id (car e))
	   (critical? (and (= len 3) (der-boolean-value (cadr e))))
	   (value (if (= len 2) (cadr e) (caddr e))))
      (make-x509-extension id critical? value))))

(define-record-type x509-extensions
  (parent <der-sequence>)
  (protocol (lambda (n)
	      (lambda (extensions)
		(unless (for-all x509-extension? extensions)
		  (springkussen-assertion-violation 'make-509-extensions
		    "X509 extension required" extensions))
		((n extensions))))))
(define (asn1-object->x509-extensions asn1-object)
  (unless (der-sequence? asn1-object)
    (springkussen-assertion-violation 'asn1-object->x509-extensions
				      "Invalid format" asn1-object))
    (make-x509-extensions
     (map asn1-object->x509-extension (asn1-collection-elements asn1-object))))

;; I'm not entirely sure if we put these here, but couldn't find
;; any better place (on PKCS#7 specification, it says these are
;; taken from X.509-88, so should be here, right?)
;; AlgorithmIdentifier  ::=  SEQUENCE  {
;;      algorithm               OBJECT IDENTIFIER,
;;      parameters              ANY DEFINED BY algorithm OPTIONAL  }
(define-record-type algorithm-identifier
  (parent <asn1-encodable-object>)
  (fields algorithm
	  parameters)
  (protocol (lambda (n)
	      (lambda (oid param)
		(unless (der-object-identifier? oid)
		  (springkussen-assertion-violation 'make-algorithm-identifier
						    "OID required" oid))
		(unless (asn1-object? param)
		  (springkussen-assertion-violation 'make-algorithm-identifier
		    "ASN1 object required" param))
		((n algorithm-identifier->asn1-object) oid param)))))
(define (algorithm-identifier->asn1-object self)
  (der-sequence
   (algorithm-identifier-algorithm self)
   (algorithm-identifier-parameters self)))
(define (asn1-object->algorithm-identifier asn1-object)
  (unless (der-sequence? asn1-object)
    (springkussen-assertion-violation 'asn1-object->algorithm-identifier
				      "Invalid format" asn1-object))
  (let ((e (asn1-collection-elements asn1-object)))
    (unless (= (length e) 2)
      (springkussen-assertion-violation 'asn1-object->algorithm-identifier
					"Invalid format" asn1-object))
    (make-algorithm-identifier (car e) (cadr e))))

;; SubjectPublicKeyInfo  ::=  SEQUENCE  {
;;      algorithm            AlgorithmIdentifier,
;;      subjectPublicKey     BIT STRING  }
(define-record-type subject-public-key-info
  (parent <asn1-encodable-object>)
  (fields algorithm
	  subject-public-key)
  (protocol (lambda (n)
	      (lambda (algorithm key)
		(unless (algorithm-identifier? algorithm)
		  (springkussen-assertion-violation
		   'make-subject-public-key-info "AlgorithmIdentifier required"
		   algorithm))
		(unless (der-bit-string? key)
		  (springkussen-assertion-violation
		   'make-subject-public-key-info "Bit string required" key))
		((n subject-public-key-info->asn1-object) algorithm key)))))
(define (subject-public-key-info->asn1-object self)
  (der-sequence
   (subject-public-key-info-algorithm self)
   (subject-public-key-info-subject-public-key self)))
(define (asn1-object->subject-public-key-info asn1-object)
  (unless (der-sequence? asn1-object)
    (springkussen-assertion-violation 'asn1-object->subject-public-key-info
      "Invalid SubjectPublicKeyInfo" asn1-object))
  (let ((e (asn1-collection-elements asn1-object)))
    (unless (= (length e) 2)
      (springkussen-assertion-violation 'asn1-object->subject-public-key-info
	"Invalid SubjectPublicKeyInfo" asn1-object))
    (make-subject-public-key-info
     (asn1-object->algorithm-identifier (car e))
     (cadr e))))
(define (bytevector->subject-public-key-info bv)
  (asn1-object->subject-public-key-info
   (bytevector->asn1-object bv)))
(define (public-key->subject-public-key-info public-key)
  (bytevector->subject-public-key-info
   (signature:export-asymmetric-key public-key)))

(define *spki-oids*
  `(("1.2.840.113549.1.1.1"  . ,*public-key-operation:rsa*)
    ;; Below RSAs shouldn't be needed as SubjectPublicKeyInfo must only
    ;; conttain the "1.2.840.113549.1.1.1"
    ("1.2.840.113549.1.1.2"  . ,*public-key-operation:rsa*)
    ("1.2.840.113549.1.1.3"  . ,*public-key-operation:rsa*)
    ("1.2.840.113549.1.1.4"  . ,*public-key-operation:rsa*)
    ("1.2.840.113549.1.1.5"  . ,*public-key-operation:rsa*)
    ("1.2.840.113549.1.1.7"  . ,*public-key-operation:rsa*)
    ("1.2.840.113549.1.1.10" . ,*public-key-operation:rsa*)
    ("1.2.840.113549.1.1.11" . ,*public-key-operation:rsa*)
    ("1.2.840.113549.1.1.12" . ,*public-key-operation:rsa*)
    ("1.2.840.113549.1.1.13" . ,*public-key-operation:rsa*)
    ("1.2.840.113549.1.1.14" . ,*public-key-operation:rsa*)
    ("2.5.8.1.1"             . ,*public-key-operation:rsa*)
    ("1.2.840.10045.2.1"     . ,*public-key-operation:ecdsa*)
    ;; TODO DSA
    ))

(define (subject-public-key-info->public-key spki)
  (define aid (subject-public-key-info-algorithm spki))
  (define oid (algorithm-identifier-algorithm aid))
  (cond ((assoc (der-object-identifier-value oid) *spki-oids*) =>
	 (lambda (slot)
	   (asymmetric-key:import-key (cdr slot)
				      (asn1-object->bytevector spki))))
	(else (springkussen-error 'subject-public-key-info->public-key
				  "Unknown OID"
				  (der-object-identifier-value oid)))))
)
