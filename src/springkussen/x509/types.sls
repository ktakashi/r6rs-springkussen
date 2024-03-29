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
	    algorithm-identifier->cipher&parameters
	    register-cipher&parameters-oid

	    make-subject-public-key-info subject-public-key-info?
	    asn1-object->subject-public-key-info ;; useful?
	    subject-public-key-info->public-key
	    bytevector->subject-public-key-info
	    subject-public-key-info->bytevector
	    public-key->subject-public-key-info
	    
	    make-rdn rdn? rdn-values

	    make-x509-name x509-name?
	    x509-name->asn1-object asn1-object->x509-name
	    x509-name->list list->x509-name
	    asn1-object->x509-name
	    x509-name->string
	    string->x509-name
	    (rename (*default-symbols* *x509-known-symbols*))
	    *rfc5280-symbols*

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
	    (springkussen signature)
	    (springkussen misc bytevectors)
	    (springkussen x509 algorithm-identifier))

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

;; RFC 5280 Section 4.1.2.4
(define *rfc5280-symbols*
  '(
    ("2.5.4.6"  . C)			;; country
    ("0.9.2342.19200300.100.1.25" . DC) ;; domainComponent
    ("2.5.4.10" . O)			;; organization
    ("2.5.4.11" . OU)			;; organization unit
    ("2.5.4.26" . DN)			;; distinguished name qualifier
    ("2.5.4.8"  . ST)			;; state or province name
    ("2.5.4.3"  . CN)			;; common name
    ("2.5.4.5"  . SERIALNUMBER)		;; serial number

    ("2.5.4.7"  . L)			;; locality
    ("2.5.4.12" . T)			;; title
    ("2.5.4.4"  . SURNAME)		;; surname
    ("2.5.4.42" . GIVENNAME)		;; given name
    ("2.5.4.43" . INITIALS)		;; initials
    ("2.5.4.44" . GENERATION)		;; generation qualifier (e.g. "Jr.")
    ("2.5.4.65" . Pseudonym)		;; Pseudonym

    ;; apparently, this is not in RFC 5280
    ;; yet seems okay to have name...
    ("2.5.4.9"  . STREET)		
    ))

(define *default-symbols*
  `(,@*rfc5280-symbols*
    ("1.2.840.113549.1.9.1"       . E)
    ("0.9.2342.19200300.100.1.1"  . UID)))
(define (rdn->list rdn using-symbols)
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
	(cond ((assoc oid using-symbols) =>
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

(define x509-name->list
  (case-lambda
   ((x509-name) (x509-name->list x509-name *default-symbols*))
   ((x509-name using-symbols)
    (unless (x509-name? x509-name)
      (springkussen-assertion-violation 'x509-name->list
					"X509 name is required" x509-name))
    (map (lambda (n) (rdn->list n using-symbols)) (x509-name-rdns x509-name)))))

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

(define x509-name->string
  (case-lambda
   ((x509-name) (x509-name->string x509-name *default-symbols*))
   ((x509-name using-symbols)
    (define escapings '(#\, #\\ #\# #\+ #\< #\> #\; #\" #\=))
    (define (escape name v out)
      (if (symbol? name)
	  (string-for-each (lambda (c)
			     (when (memv c escapings) (put-char out #\\))
			     (put-char out c)) v)
	  (let ((v (string-downcase (bytevector->hex-string (string->utf8 v)))))
	    (put-string out "#1312")
	    (put-string out v))))
    
    (let-values (((out e) (open-string-output-port)))
      (do ((lis (reverse (x509-name->list x509-name using-symbols)) (cdr lis))
	   (first? #t #f))
	  ((null? lis) (e))
	(let* ((e (car lis))
	       (a (car e))
	       (v (cadr e)))
	  (unless first? (put-string out ","))
	  (if (string? a)
	      (put-string out a)
	      (put-datum out a))
	  (put-char out #\=)
	  (escape a v out)))))))

(define *known-name-strings*
  (map symbol->string (map cdr *default-symbols*)))

(define (string->x509-name s)
  (define (string-index s start char)
    (define len (string-length s))
    (let loop ((i start))
      (cond ((= i len) #f)
	    ((eqv? (string-ref s i) char) i)
	    (else (loop (+ i 1))))))
  (define (decode-value s)
    (if (and (not (zero? (string-length s))) (eqv? (string-ref s 0) #\#))
	(let ((bv (hex-string->bytevector (substring s 1 (string-length s)))))
	  ;; not sure how to handle this but for now, we just ignore
	  ;; the first 2 bytes...
	  (utf8->string (sub-bytevector bv 2)))
	(let-values (((out e) (open-string-output-port)))
	  (let loop ((i 0))
	    (cond ((= i (string-length s)) (e))
		  ((eqv? (string-ref s i) #\\)
		   ;; Should we check the length?
		   (put-char out (string-ref s (+ i 1)))
		   (loop (+ i 2)))
		  (else (put-char out (string-ref s i)) (loop (+ i 1))))))))
  (define (next-non-whitespace-index s start)
    (let loop ((i start))
      (cond ((= i (string-length s)) i)
	    ((char-whitespace? (string-ref s i)) (loop (+ i 1)))
	    (else i))))
      
  (define (parse-name s index)
    (define (check-name n)
      (cond ((member n *known-name-strings*) (string->symbol n))
	    (else n)))
    (cond ((string-index s index #\=) =>
	   (lambda (i) (values (check-name (substring s index i)) (+ i 1))))
	  (else (springkussen-error 'string->x509-name "Invalid DN format" s))))
  (define (parse-value s index)
    (cond ((string-index s index #\,) =>
	   (lambda (i)
	     (values (decode-value (substring s index i))
		     (next-non-whitespace-index s (+ i 1)))))
	  ;; last
	  ((< index (string-length s))
	   (values (decode-value (substring s index (string-length s)))
		   (string-length s)))
	  (else (springkussen-error 'string->x509-name "Invalid DN format" s))))

  (unless (string? s)
    (springkussen-assertion-violation 'string->x509-name "string required" s))
  (let loop ((tokens '()) (index 0))
    (if (= index (string-length s))
	(list->x509-name tokens)
	(let*-values (((name next) (parse-name s index))
		      ((value next) (parse-value s next)))
	  (loop (cons (list name value) tokens) next)))))

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
(define (subject-public-key-info->bytevector spki)
  (asn1-object->bytevector spki))

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
