;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cms/akp.sls - Asymmetric Key Packages
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

;; ref:
;;  - https://datatracker.ietf.org/doc/html/rfc5958
;;  - https://datatracker.ietf.org/doc/html/rfc5208 (obsolated)
#!r6rs
(library (springkussen cms akp)
    (export cms-one-asymmetric-key? make-cms-one-asymmetric-key
	    cms-one-asymmetric-key-version
	    cms-one-asymmetric-key-private-key-algorithm
	    cms-one-asymmetric-key-private-key
	    cms-one-asymmetric-key-attributes
	    cms-one-asymmetric-key-public-key
	    asn1-object->cms-one-asymmetric-key
	    bytevector->cms-one-asymmetric-key
	    cms-one-asymmetric-key->bytevector
	    cms-one-asymmetric-key->private-key
	    private-key->cms-one-asymmetric-key

	    make-cms-private-key-info
	    cms-private-key-info?
	    asn1-object->cms-private-key-info
	    bytevector->cms-private-key-info
	    cms-private-key-info->bytevector
	    cms-private-key-info->private-key
	    private-key->cms-private-key-info
	    
	    cms-encrypted-private-key-info? make-cms-encrypted-private-key-info
	    cms-encrypted-private-key-info-encryption-algorithm
	    cms-encrypted-private-key-info-encrypted-data
	    asn1-object->cms-encrypted-private-key-info
	    bytevector->cms-encrypted-private-key-info
	    cms-encrypted-private-key-info->bytevector)
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen conditions)
	    (springkussen cms types)
	    (springkussen math ec) ;; for ec-parameter-oid
	    (springkussen misc lambda)
	    (springkussen signature) ;; for key operation
	    (springkussen signature ecdsa key)
	    (springkussen x509))

;; OneAsymmetricKey ::= SEQUENCE {
;;   version                   Version,
;;   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
;;   privateKey                PrivateKey,
;;   attributes            [0] Attributes OPTIONAL,
;;   ...,
;;   [[2: publicKey        [1] PublicKey OPTIONAL ]],
;;   ...
;; }
(define-record-type cms-one-asymmetric-key
  (parent <asn1-encodable-object>)
  (fields version private-key-algorithm private-key attributes public-key)
  (protocol (lambda (n)
	      (lambda/typed ((version der-integer?)
			     (private-key-algorithm algorithm-identifier?)
			     (private-key der-octet-string?)
			     (attributes (or #f (der-set-of? cms-attribute?)))
			     (public-key (or #f der-bit-string?)))
	       (when (and public-key (< (der-integer-value version) 2))
		 (springkussen-assertion-violation 'make-cms-one-asymmetric-key
		   "Invalid version, must be 2 or higher" version))
	       ((n cms-one-asymmetric-key->asn1-object)
		version private-key-algorithm private-key
		attributes public-key)))))
(define (cms-one-asymmetric-key->asn1-object self)
  (define (->tagged o tag)
    (and o (make-der-tagged-object tag #f o)))
  (make-der-sequence
   (filter values
	   (list (cms-one-asymmetric-key-version self)
		 (cms-one-asymmetric-key-private-key-algorithm self)
		 (cms-one-asymmetric-key-private-key self)
		 (->tagged (cms-one-asymmetric-key-attributes self) 0)
		 (->tagged (cms-one-asymmetric-key-public-key self) 1)))))

(define/typed (asn1-object->cms-one-asymmetric-key (asn1-object der-sequence?))
  (let ((e (asn1-collection-elements asn1-object)))
    (when (< (length e) 3)
      (springkussen-assertion-violation 'asn1-object->cms-private-key-info
					"Invalid format"))
    (let ((attr (asn1-collection:find-tagged-object asn1-object 0))
	  (public-key (asn1-collection:find-tagged-object asn1-object 1)))
      (make-cms-one-asymmetric-key
       (car e)
       (asn1-object->algorithm-identifier (cadr e))
       (caddr e)
       attr public-key))))

(define (bytevector->cms-one-asymmetric-key bv)
  (asn1-object->cms-one-asymmetric-key (bytevector->asn1-object bv)))
(define/typed (cms-one-asymmetric-key->bytevector
	       (cms-one-asymmetric-key cms-one-asymmetric-key?))
  (asn1-object->bytevector cms-one-asymmetric-key))

(define (oid->private-key-operation oid)
  (cond ((string=? oid "1.2.840.10045.2.1") *private-key-operation:ecdsa*)
	((string=? oid "1.2.840.113549.1.1.1") *private-key-operation:rsa*)
	(else (springkussen-assertion-violation
	       'oid->private-key-operation "Not supported yet" oid))))

(define (ensure-named-curve bv aid op)
  (if (eq? op *private-key-operation:ecdsa*)
      (let ((seq (bytevector->asn1-object bv)))
	(unless (der-sequence? seq)
	  (springkussen-assertion-violation 'cms-one-asymmetric-key->private-key
					    "Unknown ECDSA key format"))
	(let ((tag0 (asn1-collection:find-tagged-object seq 0)))
	  (if tag0
	      bv ;; okay something is there :)
	      (let-values (((version private-key . rest)
			    (apply values (asn1-collection-elements seq))))
		(asn1-object->bytevector
		 (apply der-sequence
			version
			private-key
			(make-der-tagged-object 0 #t
			 (algorithm-identifier-parameters aid))
			rest))))))
      bv))

(define/typed (cms-one-asymmetric-key->private-key
	       (asymmetric-key cms-one-asymmetric-key?))
  (let* ((aid (cms-one-asymmetric-key-private-key-algorithm asymmetric-key))
	 (oid (der-object-identifier-value
	       (algorithm-identifier-algorithm aid)))
	 (private-key (cms-one-asymmetric-key-private-key asymmetric-key))
	 (op (oid->private-key-operation oid)))
    (asymmetric-key:import-key op
			       (ensure-named-curve
				(der-octet-string-value private-key)
				aid op))))

(define/typed (private-key->cms-one-asymmetric-key (private-key private-key?))
  (define (private-key->aid private-key)
    (cond ((ecdsa-private-key? private-key)
	   (let ((ec-oid (ec-parameter-oid
			  (ecdsa-private-key-ec-parameter private-key))))
	     (make-algorithm-identifier
	      (make-der-object-identifier "1.2.840.10045.2.1")
	      (make-der-object-identifier ec-oid))))
	  ((rsa-private-key? private-key)
	   (make-algorithm-identifier
	    (make-der-object-identifier "1.2.840.113549.1.1.1")))
	  (else (springkussen-assertion-violation
		 'private-key->cms-one-asymmetric-key "Not supported yet"))))
  (let ((bv (signature:export-asymmetric-key private-key))
	(aid (private-key->aid private-key)))
    (make-cms-one-asymmetric-key (make-der-integer 0)
				 aid
				 (make-der-octet-string bv) #f #f)))

;; RFC 5208 compatible thing
(define make-cms-private-key-info
  (case-lambda/typed
   ((v pa pk) (make-cms-private-key-info v pa pk #f))
   (((version der-integer?)
     (private-key-algorithm algorithm-identifier?)
     (private-key der-octet-string?)
     (attributes (or #f (der-set-of? cms-attribute?))))
    (unless (zero? (der-integer-value version))
      (springkussen-assertion-violation 'make-cms-private-key-info
					"Invalid version, must be 0" version))
    (make-cms-one-asymmetric-key version
				 private-key-algorithm
				 private-key
				 attributes
				 #f))))
(define (cms-private-key-info? obj)
  (and (cms-one-asymmetric-key? obj)
       (zero? (der-integer-value (cms-one-asymmetric-key-version obj)))))

(define (asn1-object->cms-private-key-info asn1-object)
  (let ((r (asn1-object->cms-one-asymmetric-key asn1-object)))
    (unless (cms-private-key-info? r)
      (springkussen-error 'asn1-object->cms-private-key-info
			  "Invalid format"))
    r))
(define (bytevector->cms-private-key-info bv)
  (asn1-object->cms-private-key-info (bytevector->asn1-object bv)))
(define/typed (cms-private-key-info->bytevector
	       (private-key-info cms-private-key-info?))
  (asn1-object->bytevector private-key-info))

(define cms-private-key-info->private-key cms-one-asymmetric-key->private-key)
(define private-key->cms-private-key-info private-key->cms-one-asymmetric-key)

;; EncryptedPrivateKeyInfo ::= SEQUENCE {
;;   encryptionAlgorithm  EncryptionAlgorithmIdentifier,
;;   encryptedData        EncryptedData }
;; EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
;;                                    { CONTENT-ENCRYPTION,
;;                                      { KeyEncryptionAlgorithms } }
;; EncryptedData ::= OCTET STRING
(define-record-type cms-encrypted-private-key-info
  (parent <asn1-encodable-object>)
  (fields encryption-algorithm
	  encrypted-data)
  (protocol (lambda (n)
	      (lambda/typed ((encryption-algorithm algorithm-identifier?)
			     (encrypted-data der-octet-string?))
	        ((n simple-asn1-encodable-object->der-sequence)
		 encryption-algorithm encrypted-data)))))
(define/typed (asn1-object->cms-encrypted-private-key-info
	       (asn1-object der-sequence?))
  (let ((e (asn1-collection-elements asn1-object)))
    (unless (= (length e) 2)
      (springkussen-assertion-violation
       'asn1-object->cms-encrypted-private-key-info "Invalid format"))
    (make-cms-encrypted-private-key-info
     (asn1-object->algorithm-identifier (car e))
     (cadr e))))

(define (bytevector->cms-encrypted-private-key-info bv)
  (asn1-object->cms-encrypted-private-key-info (bytevector->asn1-object bv)))
(define/typed (cms-encrypted-private-key-info->bytevector
	       (encrypted-private-key-info cms-encrypted-private-key-info?))
  (asn1-object->bytevector encrypted-private-key-info))
)
