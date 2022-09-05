;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/pem.sls - PEM APIs
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
(library (springkussen pem)
    (export pem-object?
	    read-pem-object string->pem-object
	    write-pem-object pem-object->string

	    x509-certificate-pem-object?
	    pem-object->x509-certificate x509-certificate->pem-object

	    x509-certificate-revocation-list-pem-object?
	    pem-object->x509-certificate-revocation-list
	    x509-certificate-revocation-list->pem-object
	    
	    private-key-pem-object?
	    pem-object->private-key private-key->pem-object

	    public-key-pem-object?
	    pem-object->public-key public-key->pem-object
	    
	    x509-certificate-signing-request-pem-object?
	    pem-object->x509-certificate-signing-request
	    x509-certificate-signing-request->pem-object)
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen conditions)
	    (springkussen misc lambda)
	    (springkussen pem reader)
	    (springkussen signature)
	    (springkussen x509)
	    (only (springkussen x509 types)
		  bytevector->subject-public-key-info
		  public-key->subject-public-key-info
		  subject-public-key-info->public-key)
	    (springkussen cms))

(define-syntax make-pem-object-predicate
  (syntax-rules ()
    ((_ labels ...)
     (lambda (obj)
       (and (pem-object? obj)
	    (let ((label (pem-object-label obj)))
	      (or (string=? labels label) ...)))))))
(define-syntax make-pem-object->object
  (syntax-rules ()
    ((_ pred converter)
     (let ((conv converter) (p pred))
       (lambda/typed ((pem-object p))
	 (conv (pem-object-content pem-object)))))))

(define-syntax make-object->pem-object
  (syntax-rules ()
    ((_ pred label ->bytevector)
     (let ((conv ->bytevector))
       (lambda/typed ((obj pred)) (make-pem-object label (conv obj)))))))

(define-syntax define-pem-object-procedures
  (syntax-rules ()
    ((_ (pred ->obj ->pem-object) pred2 converter ->bytevector label label* ...)
     (begin
       (define pred (make-pem-object-predicate label label* ...))
       (define ->obj (make-pem-object->object pred converter))
       (define ->pem-object
	 (make-object->pem-object pred2 label ->bytevector))))))

(define-pem-object-procedures
  (x509-certificate-pem-object? pem-object->x509-certificate
				x509-certificate->pem-object)
  x509-certificate?
  bytevector->x509-certificate
  x509-certificate->bytevector
  "CERTIFICATE"
  ;; non standard, but I see X509 CERTIFICATE so often
  "X509 CERTIFICATE"
  "X.509 CERTIFICATE")

(define-pem-object-procedures
  (x509-certificate-revocation-list-pem-object?
   pem-object->x509-certificate-revocation-list
   x509-certificate-revocation-list->pem-object)
  x509-certificate-revocation-list?
  bytevector->x509-certificate-revocation-list
  x509-certificate-revocation-list->bytevector
  "X509 CRL"
  ;; rarely used, but in case :)
  "CRL")

(define-pem-object-procedures
  (x509-certificate-signing-request-pem-object?
   pem-object->x509-certificate-signing-request
   x509-certificate-signing-request->pem-object)
  x509-certificate-signing-request?
  bytevector->x509-certificate-signing-request
  x509-certificate-signing-request->bytevector
  "CERTIFICATE REQUEST"
  "NEW CERTIFICATE REQUEST")

(define-pem-object-procedures
  (private-key-pem-object? pem-object->private-key private-key->pem-object)
  private-key?
  (lambda (obj)
    (cms-one-asymmetric-key->private-key
     (bytevector->cms-one-asymmetric-key obj)))
  (lambda (key)
    (asn1-object->bytevector (private-key->cms-one-asymmetric-key key)))
  "PRIVATE KEY")

(define-pem-object-procedures
  (public-key-pem-object? pem-object->public-key public-key->pem-object)
  public-key?
  (lambda (obj)
    (subject-public-key-info->public-key
     (bytevector->subject-public-key-info (pem-object-content obj))))
  (lambda (key)
    (asn1-object->bytevector (public-key->subject-public-key-info key)))
  "PUBLIC KEY")

)
