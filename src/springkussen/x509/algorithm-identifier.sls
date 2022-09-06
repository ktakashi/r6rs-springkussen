;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/x509/algorithm-identifier.sls - X.509 AlgorithmIdentifier types
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

;; A library to avoid unnecessary dependencies import
;; This should only be used in (springkussen cipher symmetric),
;; (springkussen cipher asymmetric) or (springkussen cipher password)
;; Ugly...
#!r6rs
(library (springkussen x509 algorithm-identifier)
    (export make-algorithm-identifier algorithm-identifier?
	    algorithm-identifier-algorithm algorithm-identifier-parameters
	    asn1-object->algorithm-identifier ;; useful?
	    algorithm-identifier->cipher&parameters
	    register-cipher&parameters-oid)
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen conditions)
	    (springkussen misc lambda))

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
	      (case-lambda
	       ((oid)
		(unless (der-object-identifier? oid)
		  (springkussen-assertion-violation 'make-algorithm-identifier
						    "OID required" oid))
		((n simple-asn1-encodable-object->der-sequence) oid #f))
	       ((oid param)
		(unless (der-object-identifier? oid)
		  (springkussen-assertion-violation 'make-algorithm-identifier
						    "OID required" oid))
		(unless (asn1-object? param)
		  (springkussen-assertion-violation 'make-algorithm-identifier
		    "ASN1 object required" param))
		((n simple-asn1-encodable-object->der-sequence) oid param))))))

(define (asn1-object->algorithm-identifier asn1-object)
  (unless (der-sequence? asn1-object)
    (springkussen-assertion-violation 'asn1-object->algorithm-identifier
				      "Invalid format" asn1-object))
  (let ((e (asn1-collection-elements asn1-object)))
    (apply make-algorithm-identifier e)))

;; Algorithm identifier utilities
;; TODO I don't have any better locations other than here...
;; TODO would be nice if we use CLOS instead of this...
(define-syntax define-algorithm-identifier->cipher&parameters
  (syntax-rules ()
    ((_ ->cipher&parameter register)
     (begin
       (define *oid-table* (make-hashtable string-hash string=?))
       (define/typed (->cipher&parameter
		      (aid algorithm-identifier?))
	 (define oid
	   (der-object-identifier-value (algorithm-identifier-algorithm aid)))
	 ((cond ((hashtable-ref *oid-table* oid #f))
		(else (springkussen-error
		       'algorithm-identifier->cipher&parameters
		       "Unsupported OID" oid))) aid))
       (define/typed (%register-cipher&parameters-oid (oid string?)
						     (proc procedure?))
	 (hashtable-set! *oid-table* oid proc)
	 proc)
       (define-syntax register
	 (syntax-rules ()
	   ((_ oid proc)
	    (define dummy (%register-cipher&parameters-oid oid proc)))))))))
(define-algorithm-identifier->cipher&parameters
  algorithm-identifier->cipher&parameters
  register-cipher&parameters-oid)
)
