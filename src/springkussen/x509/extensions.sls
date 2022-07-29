;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/x509/extensions.sls - X.509 standard extensions
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
(library (springkussen x509 extensions)
    (export make-x509-general-names x509-general-names?

	    x509-general-name?
	    other-name->x509-general-name
	    rfc822-name->x509-general-name
	    dns-name->x509-general-name
	    directory-name->x509-general-name
	    uniform-resource-identifier->x509-general-name
	    ip-address->x509-general-name
	    registered-id->x509-general-name

	    make-x509-authority-key-identifier-extension
	    x509-authority-key-identifier-extension?
	    make-x509-authority-key-identifier x509-authority-key-identifier?
	    x509-authority-key-identifier-key-identifier
	    x509-authority-key-identifier-authority-cert-issuer
	    x509-authority-key-identifier-serial-number

	    x509-extension->standard-extension
	    x509-extensions->standard-extensions
	    
	    describe-x509-extensions
	    describe-x509-extension)
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen conditions)
	    (springkussen misc bytevectors)
	    (springkussen x509 types))

;; GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
(define-record-type x509-general-names
  (parent <der-sequence>)
  (protocol (lambda (n)
	      (lambda (list)
		(unless (for-all x509-general-name? list)
		  (springkussen-assertion-violation 'make-x509-general-names
		    "List of X509 general name required" list))
		((n list))))))
(define (asn1-object->x509-general-names asn1-object)
  (unless (der-sequence? asn1-object)
    (springkussen-assertion-violation 'asn1-object->x509-general-names
				      "Invalid format" asn1-object))
  (make-x509-general-names (map asn1-object->x509-general-name
				(asn1-collection-elements asn1-object))))
;; GeneralName ::= CHOICE {
;;      otherName                       [0]     OtherName,
;;      rfc822Name                      [1]     IA5String,
;;      dNSName                         [2]     IA5String,
;;      x400Address                     [3]     ORAddress,
;;      directoryName                   [4]     Name,
;;      ediPartyName                    [5]     EDIPartyName,
;;      uniformResourceIdentifier       [6]     IA5String,
;;      iPAddress                       [7]     OCTET STRING,
;;      registeredID                    [8]     OBJECT IDENTIFIER }
(define-record-type x509-general-name
  (parent <asn1-encodable-object>)
  (fields tag string)
  (protocol (lambda (n)
	      (lambda (tag string)
		((n x509-general-name->asn1-object) tag string)))))
(define (x509-general-name->asn1-object self)
  (let ((tag (x509-general-name-tag self)))
    (make-der-tagged-object tag (= tag 4)
     (x509-general-name-string self))))
(define (asn1-object->x509-general-name asn1-object)
  (define (err)
    (springkussen-assertion-violation 'asn1-object->x509-general-name
				      "Invalid format" asn1-object))
  (define (asn1-object->other-name-x509-general-name obj)
    (unless (der-sequence? obj) (err))
    (let ((e (asn1-collection-elements obj)))
      (unless (= (length e) 2) (err))
      (unless (der-object-identifier? (car e)) (err))
      (unless (der-tagged-object? (cadr e)) (err))
      (other-name->x509-general-name (der-object-identifier-value (car e))
				     (der-tagged-object-obj (cadr e)))))
  (define (der-string->general-name s ctr)
    (unless (der-octet-string? s) (err))
    (ctr (utf8->string (der-octet-string-value s))))
  (unless (der-tagged-object? asn1-object) (err))
  (let ((tag-no (der-tagged-object-tag-no asn1-object))
	(obj (der-tagged-object-obj asn1-object)))
    (case tag-no
      ((0) (asn1-object->other-name-x509-general-name obj)) ;; other-name
      ((1) (der-string->general-name obj rfc822-name->x509-general-name))
      ((2) (der-string->general-name obj dns-name->x509-general-name))
      ((4) (directory-name->x509-general-name (asn1-object->x509-name obj)))
      ((6) (der-string->general-name obj
	     uniform-resource-identifier->x509-general-name))
      ((7)
       (unless (der-octet-string? obj) (err))
       (ip-address->x509-general-name (der-octet-string-value obj)))
      ((8)
       (unless (der-octet-string? obj) (err))
       (registered-id->x509-general-name
	(der-object-identifier-value
	 (bytevector->der-object-identifier (der-octet-string-value obj)))))
      (else
       (springkussen-error 'asn1-object->x509-general-name
			   "Not supported")))))
(define (other-name->x509-general-name oid value)
  (make-x509-general-name
   0 (der-sequence (make-der-object-identifier oid)
		   (make-der-tagged-object 0 #t value))))

(define (rfc822-name->x509-general-name s)
  (make-x509-general-name 1 (make-der-ia5-string s)))
(define (dns-name->x509-general-name s)
  (make-x509-general-name 2 (make-der-ia5-string s)))
;; no support for x400Address for now
(define (directory-name->x509-general-name name)
  (unless (x509-name? name) 
    (springkussen-assertion-violation 'directory-name->x509-general-name
				      "X.509 name required"))
  (make-x509-general-name 4 name))
;; no ediPartyName for now
(define (uniform-resource-identifier->x509-general-name s)
  (make-x509-general-name 6 (make-der-ia5-string s)))
(define (ip-address->x509-general-name bv)
  (make-x509-general-name 7 (make-der-octet-string bv)))
(define (registered-id->x509-general-name oid)
  (make-x509-general-name 8 (make-der-object-identifier oid)))

(define (x509-general-name->string gn)
  (define (other-name->string s)
    (define e (asn1-collection-elements s))
    (define oid (der-object-identifier-value (car e)))
    (define v (cadr e))
    (string-append oid "="
		   (bytevector->hex-string (asn1-object->bytevector v))))
  (define tag (x509-general-name-tag gn))
  (define s (x509-general-name-string gn))
  (case tag
    ((0) (other-name->string s))
    ((1 2 6) (asn1-string-value s))
    ((4) (x509-name->string s))
    ((7) (bytevector->hex-string (der-octet-string-value s)))
    ((8) (der-object-identifier-value s))
    (else "***Unknown General Name***")))

;; AuthorityKeyIdentifier ::= SEQUENCE {
;;    keyIdentifier             [0] KeyIdentifier           OPTIONAL,
;;    authorityCertIssuer       [1] GeneralNames            OPTIONAL,
;;    authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
(define x509-authority-key-identifier-oid
  (make-der-object-identifier "2.5.29.35"))
(define-record-type x509-authority-key-identifier
  (parent <asn1-encodable-object>)
  (fields key-identifier authority-cert-issuer serial-number)
  (protocol (lambda (n)
	      (define (check-bv ki)
		(unless (bytevector? ki)
		  (springkussen-assertion-violation
		   'make-x509-authority-key-identifier
		   "keyIdentifier must be a bytevector" ki)))
	      (define (check-sn sn)
		(unless (integer? sn)
		  (springkussen-assertion-violation
		   'make-x509-authority-key-identifier
		   "serialNumber must be an integer" sn)))
	      (define (check-gn n)
		(unless (x509-general-names? n)
		  (springkussen-assertion-violation
		   'make-x509-authority-key-identifier
		   "authorityCertIssuer must be a general-names" n)))
	      (case-lambda
	       ((ki)
		(check-bv ki)
		((n x509-authority-key-identifier->asn1-object)
		 ki #f #f))
	       ((aci sn)
		(check-gn aci)
		(check-sn sn)
		((n x509-authority-key-identifier->asn1-object) #f aci sn))
	       ((ki aci sn)
		(check-bv ki)
		(check-gn aci)
		(check-sn sn)
		((n x509-authority-key-identifier->asn1-object) ki aci sn))))))
(define (x509-authority-key-identifier->asn1-object aki)
  (define ki (x509-authority-key-identifier-key-identifier aki))
  (define aci (x509-authority-key-identifier-authority-cert-issuer aki))
  (define sn (x509-authority-key-identifier-serial-number aki))
  (make-der-sequence
   (filter values
     (list (and ki (make-der-tagged-object 0 #f (make-der-octet-string ki)))
	   (and aci (make-der-tagged-object 1 #f aci))
	   (and sn (make-der-tagged-object 2 #f (make-der-integer sn)))))))
		
(define-record-type x509-authority-key-identifier-extension
  (parent <x509-extension>)
  (fields value)
  (protocol (lambda (n)
	      (define oid x509-authority-key-identifier-oid)
	      (define (->octet-string v)
		(make-der-octet-string (asn1-object->bytevector v)))
	      (lambda (aki)
		(unless (x509-authority-key-identifier? aki)
		  (springkussen-assertion-violation 
		   'make-x509-authority-key-identifier-extension
		   "AuthorityKeyIndentifier required" aki))
		((n oid #f (->octet-string aki)) aki)))))
(define (asn1-object->x509-authority-key-identifier asn1-object)
  (define (err)
    (springkussen-assertion-violation
     'asn1-object->x509-authority-key-identifier "Invalid format" asn1-object))
  (define (find-tag e* tag)
    (exists (lambda (e)
	      (and (der-tagged-object? e)
		   (= (der-tagged-object-tag-no e) tag)
		   (der-tagged-object-obj e))) e*))
  (define (serial-number->integer sn)
    (if (der-integer? sn)
	(der-integer-value sn)
	(bytevector->uinteger (der-octet-string-value sn) (endianness big))))
  (define (ensure-sequence o)
    (cond ((not o) o)
	  ((der-sequence? o) o)
	  (else (der-sequence o))))
  (unless (der-sequence? asn1-object) (err))
  (let ((v* (asn1-collection-elements asn1-object)))
    (if (null? v*)
	(make-x509-authority-key-identifier)
	(let ((ki (find-tag v* 0))
	      (aci (ensure-sequence (find-tag v* 1)))
	      (sn (find-tag v* 2)))
	  (unless (or (not ki) (der-octet-string? ki)) (err))
	  (unless (or (and (not aci) (not sn)) (and aci sn)) (err))
	  (when (and aci sn)
	    (unless (der-sequence? aci) (err))
	    (unless (or (der-octet-string? sn) (der-integer? sn)) (err)))
	  (cond ((and ki aci sn)
		 (make-x509-authority-key-identifier
		  (der-octet-string-value ki)
		  (asn1-object->x509-general-names aci)
		  (serial-number->integer sn)))
		(ki (make-x509-authority-key-identifier
		     (der-octet-string-value ki)))
		(else (make-x509-authority-key-identifier
		       (asn1-object->x509-general-names aci)
		       (serial-number->integer sn))))))))
		   
(define (x509-extension->standard-extension x509-extension)
  (define id (x509-extension-id x509-extension))
  (cond ((asn1-object=? id x509-authority-key-identifier-oid)
	 (make-x509-authority-key-identifier-extension
	  (asn1-object->x509-authority-key-identifier
	   (bytevector->asn1-object
	    (der-octet-string-value (x509-extension-value x509-extension))))))
	(else x509-extension)))

(define (x509-extensions->standard-extensions x509-extensions)
  (make-x509-extensions (map x509-extension->standard-extension
			     (asn1-collection-elements x509-extensions))))

(define describe-x509-extensions
  (case-lambda
   ((x509-extensions)
    (describe-x509-extensions x509-extensions (current-output-port)))
   ((x509-extensions out) (describe-x509-extensions x509-extensions out 0))
   ((x509-extensions out indent)
    (describe-extensions x509-extensions out indent))))
(define (describe-extensions x509-extensions out indent)
  (define (describe-extension e) (describe-x509-extension e out indent))
  (for-each describe-extension (asn1-collection-elements x509-extensions)))

(define describe-x509-extension
  (case-lambda
   ((x509-extension)
    (describe-x509-extension x509-extension (current-output-port)))
   ((x509-extension out) (describe-x509-extension x509-extension out 0))
   ((x509-extension out indent)
    (describe-extension x509-extension out indent))))
(define (describe-extension x509-extension out indent)
  (define (put-indent)
    (do ((i 0 (+ i 1))) ((= i (* indent 2))) (put-char out #\space)))
  (define (ps msg) (put-indent) (put-string out msg))
  (define (nl) (newline out))
  (define (pl msg) (ps msg) (nl))
  (define (n num) (put-string out (number->string num)))
  (define (s str) (put-string out str))
  
  (define id (x509-extension-id x509-extension))
  (define critical? (x509-extension-critical? x509-extension))
  (define value (x509-extension-value x509-extension))
  (cond ((x509-authority-key-identifier-extension? x509-extension)
	 (pl "AuthorityKeyIdentifier: ")
	 (ps "       OID: ") (s (der-object-identifier-value id)) (nl)
	 (ps "  Critical: ") (s (if critical? "True" "False")) (nl)
	 (let ((aki
		(x509-authority-key-identifier-extension-value x509-extension)))
	   (let ((ki (x509-authority-key-identifier-key-identifier aki))
		 (aci (x509-authority-key-identifier-authority-cert-issuer aki))
		 (sn (x509-authority-key-identifier-serial-number aki)))
	     (when ki
	       (ps "  [0]             keyIdentifier: ")
	       (s (bytevector->hex-string ki))
	       (nl))
	     (when aci
	       (pl "  [1]       authorityCertIssuer: ")
	       (for-each (lambda (gn)
			   (ps "")
			   (ps " [")
			   (n (x509-general-name-tag gn))
			   (s "]: ")
			   (s (x509-general-name->string gn))
			   (nl))
			 (asn1-collection-elements aci)))
	     (when aci
	       (ps "  [2] authorityCertSerialNumber: ")
	       (n sn)
	       (nl)))))
	(else
	 (describe-asn1-object x509-extension out indent))))
	 
)
