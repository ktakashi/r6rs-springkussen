;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/signature/ecdsa/key.sls - ECDSA keys
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
(library (springkussen signature ecdsa key)
    (export ecdsa-private-key?
	    ecdsa-private-key-d ecdsa-private-key-ec-parameter
	    ecdsa-private-key-public-key

	    ecdsa-public-key?
	    ecdsa-public-key-Q
	    ecdsa-public-key-ec-parameter

	    make-ecdsa-ec-parameter ecdsa-ec-parameter?
	    make-ecdsa-public-key-parameter ecdsa-public-key-parameter?
	    make-ecdsa-private-key-parameter ecdsa-private-key-parameter?

	    *ecdsa-key-factory*
	    *ecdsa-key-pair-factory*

	    *ecdsa-private-key-operation*
	    *ecdsa-public-key-operation*

	    ;; curves
	    ec-parameter?
	    NIST-P-192 secp192r1
	    NIST-P-224 secp224r1
	    NIST-P-256 secp256r1
	    NIST-P-384 secp384r1
	    NIST-P-521 secp521r1
		                
	    NIST-K-163 sect163k1
	    NIST-K-233 sect233k1
	    NIST-K-283 sect283k1
	    NIST-K-409 sect409k1
	    NIST-K-571 sect571k1
		                
	    NIST-B-163 sect163r2
	    NIST-B-233 sect233r1
	    NIST-B-283 sect283r1
	    NIST-B-409 sect409r1
	    NIST-B-571 sect571r1

	    secp192k1
	    secp224k1
	    secp256k1

	    sect163r1
	    sect239k1
	    sect113r1

	    )
    (import (rnrs)
	    (springkussen asn1)
	    ;; Reuse it to align with RSA key
	    (springkussen cipher key)
	    (springkussen cipher asymmetric key)
	    ;; reusing random parameter
	    (springkussen cipher asymmetric scheme rsa)
	    (springkussen conditions)
	    (springkussen math ec)
	    (springkussen misc bytevectors)
	    (springkussen random))

(define-record-type ecdsa-private-key
  (parent <private-key>)
  (fields d
	  ec-parameter
	  public-key))

(define-record-type ecdsa-public-key
  (parent <public-key>)
  (fields Q
	  ec-parameter))

(define-key-parameter <ecdsa-ec-parameter>
  make-ecdsa-ec-parameter ecdsa-ec-parameter?
  (ec-parameter key-parameter-ec-parameter))

(define (ecdsa-key-pair-generator key-parameter)
  (define (read-random-bits prng nbits)
    (let ((bv (random-generator:read-random-bytes prng (div nbits 8))))
      (bytevector->uinteger bv (endianness big))))
  (define ec-parameter (key-parameter-ec-parameter key-parameter secp256r1))
  (define prng
    (key-parameter-random-generator key-parameter default-random-generator))

  (let* ((n (ec-parameter-n ec-parameter))
	 (nbits (bitwise-length n))
	 (G (ec-parameter-g ec-parameter))
	 (curve (ec-parameter-curve ec-parameter)))
    (do ((d (read-random-bits prng nbits) (read-random-bits prng nbits)))
	((and (> d 2) (< d n))
	 (let ((pub (make-ecdsa-public-key (ec-point-mul curve G d)
					   ec-parameter)))
	   (make-key-pair (make-ecdsa-private-key d ec-parameter pub)
			  pub))))))
(define *ecdsa-key-pair-factory*
  (make-key-pair-factory ecdsa-key-pair-generator))


(define-key-parameter <ecdsa-public-key-parameter>
  make-ecdsa-public-key-parameter ecdsa-public-key-parameter?
  (x key-parameter-ecdsa-public-key-x)
  (y key-parameter-ecdsa-public-key-y))
(define-key-parameter <ecdsa-private-key-parameter>
  make-ecdsa-private-key-parameter ecdsa-private-key-parameter?
  (d key-parameter-ecdsa-private-key-d))

(define (ecdsa-key-generator key-parameter)
  (define (generate-public-key key-parameter)
    (let ((ec-parameter (key-parameter-ec-parameter key-parameter #f))
	  (x (key-parameter-ecdsa-public-key-x key-parameter))
	  (y (key-parameter-ecdsa-public-key-y key-parameter)))
      (make-ecdsa-public-key (make-ec-point x y) ec-parameter)))
  
  (unless (ecdsa-ec-parameter? key-parameter)
    (springkussen-assertion-violation 'ecdsa-key-generator
				      "EC parameter is required"))
  (cond ((ecdsa-private-key-parameter? key-parameter)
	 (let ((ec-parameter (key-parameter-ec-parameter key-parameter))
	       (d (key-parameter-ecdsa-private-key-d key-parameter))
	       (public-key (and (ecdsa-public-key-parameter? key-parameter)
				(generate-public-key key-parameter))))
	   (make-ecdsa-private-key d ec-parameter public-key)))
	((ecdsa-public-key-parameter? key-parameter)
	 (generate-public-key key-parameter))
	(else (springkussen-assertion-violation 'ecdsa-key-generator
						"Unknown parameter"))))
(define *ecdsa-key-factory* (make-key-factory ecdsa-key-generator))	   

;;; Public key operations
;; We need to export as SubjectPublicKeyInfo
;; Just encoding Q requires curve, so not even possible without it...
(define (ecdsa-public-key-exporter ecdsa-key)
  (unless (ecdsa-public-key? ecdsa-key)
    (springkussen-assertion-violation 'ecdsa-public-key-exporter
				      "ECDSA public key required"))
  (let* ((param (ecdsa-public-key-ec-parameter ecdsa-key))
	 (curve (ec-parameter-curve param)))
    (unless curve
      (springkussen-assertion-violation 'ecdsa-public-key-exporter
					"No EC parameter is set for the key"))
    
    (asn1-object->bytevector
     (der-sequence
      (der-sequence id-ec-public-key
		    (if (ec-parameter-oid param)
			(make-der-object-identifier (ec-parameter-oid param))
			(ec-parameter->asn1-object param)))
      (make-der-bit-string
       (encode-ec-point curve (ecdsa-public-key-Q ecdsa-key)))))))

(define (ecdsa-public-key-importer bv)
  (define (err)
    (springkussen-assertion-violation 'ecdsa-public-key-importer
				      "Invalid ECDSA public key format"))
  (let ((sequence (bytevector->asn1-object bv)))
    (unless (der-sequence? sequence) (err))
    (let ((elements (asn1-collection-elements sequence)))
      (unless (= (length elements) 2) (err))
      (unless (and (der-sequence? (car elements))
		   (der-bit-string? (cadr elements))) (err))
      (let ((aid (asn1-collection-elements (car elements)))
	    (spk (cadr elements)))
	(unless (asn1-object=? (car aid) id-ec-public-key) (err))
	(let* ((aid-param (cadr aid))
	       (p (cond ((der-object-identifier? aid-param)
			 (lookup-named-curve-parameter aid-param))
			;; This is not PKIK, but just for fun
			((der-sequence? aid-param)
			 (->specified-ec-domain aid-param))
			(else (err)))))
	  (make-ecdsa-public-key (decode-ec-point (ec-parameter-curve p)
						  (der-bit-string-value spk))
				 p))))))
(define *ecdsa-public-key-operation*
  (make-asymmetric-key-operation ecdsa-public-key-importer
				 ecdsa-public-key-exporter))

;;; Private key operations
;;  ECPrivateKey ::= SEQUENCE {
;;    version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
;;    privateKey     OCTET STRING,
;;    parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
;;    publicKey  [1] BIT STRING OPTIONAL
;;  }
(define (ecdsa-private-key-exporter ecdsa-key)
  (unless (ecdsa-private-key? ecdsa-key)
    (springkussen-assertion-violation 'ecdsa-private-key-exporter
				      "ECDSA private key is required"))
  (let* ((param (ecdsa-private-key-ec-parameter ecdsa-key))
	 (curve (and param (ec-parameter-curve param)))
	 (oid (and param (ec-parameter-oid param)))
	 (pub (ecdsa-private-key-public-key ecdsa-key))
	 (d (ecdsa-private-key-d ecdsa-key)))
    (asn1-object->bytevector
     (apply
      der-sequence
      (make-der-integer 1)
      (make-der-octet-string (uinteger->bytevector d (endianness big)))
      (filter values
	      (list
	       (and param
		    (make-der-tagged-object 0 #t
		     (if oid
			 (make-der-object-identifier oid)
			 (ec-parameter->asn1-object param))))
	       (and pub
		    (make-der-tagged-object 1 #t
		     (make-der-bit-string
		      (encode-ec-point curve (ecdsa-public-key-Q pub)))))))))))

(define (ecdsa-private-key-importer bv)
  (define (err)
    (springkussen-assertion-violation 'ecdsa-private-key-importer
				      "Invalid ECDSA private key format"))
  (define (find-tag-obj seq n)
    (cond ((asn1-collection:find-tagged-object seq n) => der-tagged-object-obj)
	  (else #f)))

  (let ((obj (bytevector->asn1-object bv)))
    (unless (der-sequence? obj) (err))
    (let ((e (asn1-collection-elements obj)))
      (when (< (length e) 2) (err))
      (let ((first (car e)))
	(unless (and (der-integer? first)
		     (= (der-integer-value first) 1)) (err))
	(let ((tag0 (find-tag-obj obj 0)))
	  (unless tag0
	    (springkussen-assertion-violation 'ecdsa-private-key-importer
	      "[0] parameters field is required"))
	  (let ((param (if (der-object-identifier? tag0)
			   (lookup-named-curve-parameter tag0)
			   (->specified-ec-domain tag0))))
	    (make-ecdsa-private-key
	     (bytevector->uinteger (der-octet-string-value (cadr e))
				   (endianness big))
	     param
	     (let ((p (find-tag-obj obj 1)))
	       (and p (make-ecdsa-public-key
		       (decode-ec-point (ec-parameter-curve param)
					(der-octet-string-value p))
		       param))))))))))

(define *ecdsa-private-key-operation*
  (make-asymmetric-key-operation ecdsa-private-key-importer
				 ecdsa-private-key-exporter))
  
;; Below are not APIs
(define (lookup-named-curve-parameter oid)
  (lookup-ec-parameter (der-object-identifier-value oid)))

(define id-ec-public-key (make-der-object-identifier "1.2.840.10045.2.1"))
(define id-prime-field (make-der-object-identifier "1.2.840.10045.1.1"))
(define id-f2m-field (make-der-object-identifier "1.2.840.10045.1.2"))

;; From https://www.secg.org/sec1-v2.pdf
;;  SpecifiedECDomain ::= SEQUENCE {
;;    version INTEGER { ecpVer1(1) } (ecpVer1),
;;    fieldID FieldID {{FieldTypes}},
;;    curve   Curve,
;;    base    ECPoint,
;;    order   INTEGER,
;;    cofactor INTEGER OPTIONAL,
;;    ...
;;  }
;;  FieldTypes FIELD-ID ::= {
;;    { Prime-p IDENTIFIED BY prime-field } |
;;    { Characteristic-two IDENTIFIED BY characteristic-two-field }
;;  }
;;  ECPoint ::= OCTET STRING
;;  Curve ::= SEQUENCE {
;;    a FieldElement,
;;    b FieldElement,
;;    seed BIT STRING OPTIONAL
;;  }
;;  FieldElement ::= OCTET STRING
(define (->specified-ec-domain p)
  (define (err)
    (springkussen-assertion-violation '->specified-ec-domain
				      "Invalid ECParameters format"))
  (define (parse-field-id field-id)
    (unless (der-sequence? field-id) (err))
    (let ((objs (asn1-collection-elements field-id)))
      (when (< (length objs) 2) (err))
      (values (car objs) (cadr objs))))

  (define (parse-curve curve)
    (unless (der-sequence? curve) (err))
    (let ((obj (asn1-collection-elements curve)))
      (values (bytevector->uinteger (der-octet-string-value (car obj))
				    (endianness big))
	      (bytevector->uinteger (der-octet-string-value (cadr obj))
				    (endianness big))
	      (if (= (length obj) 3)
		  (der-bit-string-value (caddr obj))
		  #vu8()))))
  (define (make-curve field-type field-param a b)
    (define (parse-f2m-parameter f2m)
      (define param (caddr f2m))
      ;; lazy way. 
      (cond ((der-null? param) (values 0 0 0))
	    ((der-integer? param)
	     (values (der-integer-value param) 0 0))
	    ((der-sequence? param)
	     (apply values
		    (map der-integer-value (asn1-collection-elements param))))))
    
    (cond ((asn1-object=? id-prime-field field-type)
	   (make-elliptic-curve (make-ec-field-fp
				 (der-integer-value field-param)) a b))
	  ((asn1-object=? id-f2m-field field-type)
	   (let* ((f2m (asn1-collection-elements field-param))
		  (m (der-integer-value (car f2m))))
	     (let-values (((k1 k2 k3) (parse-f2m-parameter f2m)))
	       (make-elliptic-curve (make-ec-field-f2m m k1 k2 k3) a b))))
	  ;; Things we don't know
	  (else (err))))

  (define objs (asn1-collection-elements p))
  (when (< (length objs) 6) (err))
  (let-values (((field-type field-param) (parse-field-id (cadr objs)))
	       ((a b S) (parse-curve (caddr objs))))
    (let* ((Gxy (cadddr objs)) ;; base
	   (n (der-integer-value (car (cddddr objs))))
	   (h (der-integer-value (cadr (cddddr objs))))
	   (curve (make-curve field-type field-param a b))
	   (base (decode-ec-point curve (der-octet-string-value Gxy))))
      (make-ec-parameter curve base n h S))))

(define (ec-parameter->asn1-object ep)
  (define curve (ec-parameter-curve ep))
  (define field (elliptic-curve-field curve))
  (define (make-asn1-curve curve)
    (define (uinteger->der-octet-string a)
      (make-der-octet-string (uinteger->bytevector a (endianness big))))
    (make-der-sequence
     (filter values
	     (list (uinteger->der-octet-string (elliptic-curve-a curve))
		   (uinteger->der-octet-string (elliptic-curve-b curve))
		   (ec-parameter-seed ep)))))
  (define (make-asn1-field field)
    (if (ec-field-fp? field)
	(let ((p (ec-field-fp-p field)))
	  (der-sequence id-prime-field (make-der-integer p)))
	(let ((m (ec-field-f2m-m field))
	      (k1 (ec-field-f2m-k1 field))
	      (k2 (ec-field-f2m-k2 field))
	      (k3 (ec-field-f2m-k3 field)))
	  (der-sequence id-f2m-field
			(apply der-sequence
			       (make-der-integer m)
			       (cond ((and (zero? k1) (zero? k2) (zero? k3))
				      (list
				       (make-der-object-identifier
					"1.2.840.10045.1.2.3.1")
				       (make-der-null)))
				     ((and (zero? k2) (zero? k3))
				      (list
				       (make-der-object-identifier
					"1.2.840.10045.1.2.3.2")
				       (make-der-integer k1)))
				     (else
				      (list
				       (make-der-object-identifier
					"1.2.840.10045.1.2.3.3")
				       (der-sequence
					(make-der-integer k1)
					(make-der-integer k2)
					(make-der-integer k3))))))))))
  (der-sequence
   (make-der-integer 1)
   (make-asn1-field field)
   (make-asn1-curve curve)
   (make-der-octet-string (encode-ec-point curve (ec-parameter-g ep)))
   (make-der-integer (ec-parameter-n ep))
   (make-der-integer (ec-parameter-h ep))))
)
