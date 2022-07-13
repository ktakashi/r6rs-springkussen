;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/asymmetric/scheme/rsa.sls - RSA 
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
(library (springkussen cipher asymmetric scheme rsa)
    (export rsa-descriptor

	    *rsa-key-factory*
	    *rsa-key-pair-factory*

	    *rsa-public-key-operation*
	    *rsa-private-key-operation*

	    rsa-key-parameter?
	    make-rsa-public-key-parameter rsa-public-key-parameter?
	    make-rsa-private-key-parameter rsa-private-key-parameter?
	    make-rsa-crt-private-key-parameter rsa-crt-private-key-parameter?
	    make-random-generator-key-parameter random-generator-key-parameter?
	    make-key-size-key-parameter key-size-key-parameter?
	    make-public-exponent-key-parameter public-exponent-key-parameter?
	    
	    rsa-public-key-builder
	    rsa-private-key-builder
	    rsa-crt-private-key-builder

	    rsa-public-key? rsa-public-key-modulus rsa-public-key-exponent

	    rsa-private-key?
	    rsa-private-key-modulus rsa-private-key-private-exponent

	    rsa-crt-private-key?
	    rsa-crt-private-key-public-exponent rsa-crt-private-key-p
	    rsa-crt-private-key-q rsa-crt-private-key-dP
	    rsa-crt-private-key-dQ rsa-crt-private-key-qP)
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen conditions)
	    (springkussen cipher key)
	    (springkussen cipher asymmetric key)
	    (springkussen cipher asymmetric scheme descriptor)
	    (springkussen math modular)
	    (springkussen math prime)
	    (springkussen misc bytevectors)
	    (springkussen misc record)
	    (springkussen random))


;; This is by design, we don't want to expose direct key
;; access, so the state key must only be available in
;; the same library
(define-record-type rsa-state
  (parent <asymmetric-state>)
  (opaque #f)
  (fields key))

(define-record-type rsa-public-key
  (parent <public-key>)
  (fields modulus			; n
	  exponent))			; e

(define-syntax rsa-public-key-builder
  (make-record-builder rsa-public-key))

(define-record-type rsa-private-key
  (parent <private-key>)
  (fields modulus			; n
	  private-exponent))		; d
(define-syntax rsa-private-key-builder
  (make-record-builder rsa-private-key))


(define-record-type rsa-crt-private-key
  (parent rsa-private-key)
  (fields public-exponent		; e
	  p				; prime1, p
	  q				; prime2, q
	  dP				; d mod (p-1)
	  dQ				; d mod (q-1)
	  qP)				; (inverse of q) mod p
  (protocol (lambda (n)
	      (lambda (m d e p q dP dQ qP)
		((n m d) e p q
		 (or dP (mod d (- p 1)))
		 (or dQ (mod d (- q 1)))
		 (or qP (mod-inverse q p)))))))
		 
(define-syntax rsa-crt-private-key-builder
  (make-record-builder rsa-crt-private-key))


(define *rsa-min-keysize* 1024)		; should be 2046 nowadays

(define (rsa-setup key param)
  ;; TODO for-encryption? from the param
  (make-rsa-state #t (private-key? key) key))

(define (rsa-encrypt key pt ps)
  (let ((in (make-bytevector (- (bytevector-length pt) ps))))
    (bytevector-copy! pt ps in 0 (bytevector-length in))
    (rsa-mod-expt in (rsa-state-key key) (rsa-block-size-retriever key))))

(define (rsa-decrypt key ct cs)
  (let ((in (make-bytevector (- (bytevector-length ct) cs))))
    (bytevector-copy! ct cs in 0 (bytevector-length in))
    (rsa-mod-expt in (rsa-state-key key) (rsa-block-size-retriever key))))

(define (rsa-finalize key) #t) ;; nothing to do

(define (rsa-mod-expt bv key block-size)
  (let ((chunk (bytevector->uinteger bv (endianness big))))
    (cond ((rsa-public-key? key)
	   (let ((r (mod-expt chunk
			      (rsa-public-key-exponent key)
			      (rsa-public-key-modulus key))))
	     (uinteger->bytevector r (endianness big) block-size)))
	  ((rsa-crt-private-key? key)
	   (let ((p (rsa-crt-private-key-p key))
		 (q (rsa-crt-private-key-q key))
		 (dP (rsa-crt-private-key-dP key))
		 (dQ (rsa-crt-private-key-dQ key))
		 (qP (rsa-crt-private-key-qP key)))
	     (let* ((a (mod-expt chunk dP p))  ; b ^ dP mod p
		    (b (mod-expt chunk dQ q))  ; b ^ dQ mod q
		    (c (mod (* (- a b) qP) p)) ; (a - b) * qP (mod p)
		    (d (+ b (* q c))))	       ; b + q * c
	       (uinteger->bytevector d (endianness big) block-size))))
	  ((rsa-private-key? key)
	   (let ((a (mod-expt chunk
			      (rsa-private-key-private-exponent key)
			      (rsa-private-key-modulus key))))
	     (uinteger->bytevector a (endianness big) block-size)))
	  (else
	   (springkussen-assertion-violation 'rsa-mod-expt
					     "Invalid parameter")))))

(define (rsa-block-size-retriever state)
  (define key (rsa-state-key state))
  (define for-encryption? (asymmetric-state-for-encryption? state))
  (let ((modulus (if (public-key? key)
		     (rsa-public-key-modulus key)
		     (rsa-private-key-modulus key))))
    (div (+ (bitwise-length modulus) 7) 8)))

(define rsa-descriptor
  (asymmetric-scheme-descriptor-builder
   (name "RSA")
   (block-sizer rsa-block-size-retriever)
   (setupper rsa-setup)
   (encryptor rsa-encrypt)
   (decryptor rsa-decrypt)
   (finalizer rsa-finalize)))

;; key generation
(define-key-parameter <rsa-key-parameter>
  make-rsa-key-parameter rsa-key-parameter?
  (modulus key-parameter-modulus)
  (exponent key-parameter-exponent)) ;; can be both public and private
(define-key-parameter (<rsa-public-key-parameter> <rsa-key-parameter>)
  make-rsa-public-key-parameter rsa-public-key-parameter?)
(define-key-parameter (<rsa-private-key-parameter> <rsa-key-parameter>)
  make-rsa-private-key-parameter rsa-private-key-parameter?)

(define-key-parameter (<rsa-crt-private-key-parameter> <rsa-private-key-parameter>)
  make-rsa-crt-private-key-parameter rsa-crt-private-key-parameter?
  (public-exponent key-parameter-public-exponent)
  (p key-parameter-p)
  (q key-parameter-q)
  (dP key-parameter-dP)
  (dQ key-parameter-dQ)
  (qP key-parameter-qP))

(define (rsa-key-generator key-parameter)
  (cond ((rsa-public-key-parameter? key-parameter)
	 (rsa-public-key-builder
	  (modulus (key-parameter-modulus key-parameter))
	  (exponent (key-parameter-exponent key-parameter))))
	((rsa-private-key-parameter? key-parameter)
	 (if (rsa-crt-private-key-parameter? key-parameter)
	     (rsa-crt-private-key-builder
	      (modulus (key-parameter-modulus key-parameter))
	      (private-exponent (key-parameter-exponent key-parameter))
	      (public-exponent (key-parameter-public-exponent key-parameter))
	      (p (key-parameter-p key-parameter))
	      (q (key-parameter-q key-parameter))
	      (dP (key-parameter-dP key-parameter))
	      (dQ (key-parameter-dQ key-parameter))
	      (qP (key-parameter-qP key-parameter)))
	     (rsa-private-key-builder
	      (modulus (key-parameter-modulus key-parameter))
	      (private-exponent (key-parameter-exponent key-parameter)))))
	(else
	 (springkussen-assertion-violation 'rsa-key-generator
					   "Invalid key parameter"))))
	 
(define *rsa-key-factory* (make-key-factory rsa-key-generator))

(define-key-parameter <random-generator-key-parameter>
  make-random-generator-key-parameter random-generator-key-parameter?
  (random-generator key-parameter-random-generator))
(define-key-parameter <key-size-key-parameter>
  make-key-size-key-parameter key-size-key-parameter?
  (key-size key-parameter-key-size))
(define-key-parameter <public-exponent-key-parameter>
  make-public-exponent-key-parameter public-exponent-key-parameter?
  (public-exponent rsa-key-parameter-public-exponent))

(define (rsa-key-pair-generator key-parameter)
  (define (rsa-random-prime prng size e check)
    (let loop ((p (random-generator:random prng (/ size 16))))
      (if (and (or (not check) (not (= p check)))
	       (= 1 (gcd (- p 1) e)))
	  p
	  (loop (random-generator:random prng (/ size 16))))))
  (define (make-rsa-key-pair n e d p q)
    (make-key-pair (rsa-crt-private-key-builder
		    (modulus n)
		    (private-exponent d)
		    (public-exponent e)
		    (p p)
		    (q q))
		   (rsa-public-key-builder
		    (modulus n)
		    (exponent e))))
		    
  (let ((prng (key-parameter-random-generator key-parameter
					      default-random-generator))
	(size (key-parameter-key-size key-parameter *rsa-min-keysize*))
	(e (rsa-key-parameter-public-exponent key-parameter #x10001)))
    (when (< size *rsa-min-keysize*)
      (springkussen-assertion-violation 'rsa-key-pair-generator
					"Key size too small" size))
    (unless (probable-prime? e)
      (springkussen-assertion-violation 'rsa-key-pair-generator
					"Exponent must be a prime number" e))
    (let* ((p (rsa-random-prime prng size e #f))
	   (q (rsa-random-prime prng size e p))
	   (n (* p q))
	   (phi (* (- p 1) (- q 1)))
	   (d (mod-inverse e phi)))
      (make-rsa-key-pair n e d p q))))
      
(define *rsa-key-pair-factory* (make-key-pair-factory rsa-key-pair-generator))

;; RSAPublicKey ::= SEQUENCE {
;;   modulus         INTEGER, -- n
;;   publicExponent  INTEGER  -- e
;; }
(define (rsa-public-key-importer rsa-key-bv)
  (define (err)
    (springkussen-assertion-violation 'rsa-public-key-importer
				      "Invalid RSA public key object"))
  (unless (bytevector? rsa-key-bv)
    (springkussen-assertion-violation 'rsa-public-key-importer
				      "Bytevector required"))
  (let ((seq (bytevector->asn1-object rsa-key-bv)))
    (unless (der-sequence? seq) (err))
    (let ((e (der-sequence-elements seq)))
      (unless (= (length e) 2) (err))
      (unless (for-all der-integer? e) (err))
      (rsa-public-key-builder
       (modulus (der-integer-value (car e)))
       (exponent (der-integer-value (cadr e)))))))

(define (rsa-public-key-exporter rsa-key)
  (unless (rsa-public-key? rsa-key)
    (springkussen-assertion-violation 'rsa-public-key-exporter
				      "RSA public key required"))
  (asn1-object->bytevector
   (der-sequence
    (make-der-integer (rsa-public-key-modulus rsa-key))
    (make-der-integer (rsa-public-key-exponent rsa-key)))))

(define *rsa-public-key-operation*
  (make-asymmetric-key-operation rsa-public-key-importer
				 rsa-public-key-exporter))

;;  RSAPrivateKey ::= SEQUENCE {
;;      version           Version,
;;      modulus           INTEGER,  -- n
;;      publicExponent    INTEGER,  -- e
;;      privateExponent   INTEGER,  -- d
;;      prime1            INTEGER,  -- p
;;      prime2            INTEGER,  -- q
;;      exponent1         INTEGER,  -- d mod (p-1)
;;      exponent2         INTEGER,  -- d mod (q-1)
;;      coefficient       INTEGER,  -- (inverse of q) mod p
;;      otherPrimeInfos   OtherPrimeInfos OPTIONAL -- We do not support this.
;;  }
;;  Version ::= INTEGER { two-prime(0), multi(1) }
;;     (CONSTRAINED BY
;;     {-- version must be multi if otherPrimeInfos present --})

(define (rsa-private-key-importer rsa-key-bv)
  (define (check . args)
    (unless (for-all der-integer? args)
      (springkussen-assertion-violation 'rsa-private-key-importer
					"Invalid RSA private key object")))
  (unless (bytevector? rsa-key-bv)
    (springkussen-assertion-violation 'rsa-private-key-importer
				      "Bytevector required"))
  (let ((asn1-object (bytevector->asn1-object rsa-key-bv)))
    (unless (der-sequence? asn1-object)
      (springkussen-assertion-violation 'rsa-private-key-importer
					"Invalid RSA private key object"))
    (let ((elements (asn1-collection-elements asn1-object)))
      (when (< (length elements) 9)
	(springkussen-assertion-violation 'rsa-private-key-importer
					  "Invalid RSA private key object"))
      (let ((v (car elements))
	    (m (cadr elements))
	    (e (caddr elements))
	    (pe (cadddr elements))
	    (p (car (cddddr elements)))
	    (q (cadr (cddddr elements)))
	    (dP (caddr (cddddr elements)))
	    (dQ (cadddr (cddddr elements)))
	    (qP (car (cddddr (cddddr elements)))))
	(check v m e pe p q dP dQ qP)
	(rsa-crt-private-key-builder
	 (modulus (der-integer-value m))
	 (private-exponent (der-integer-value pe))
	 (public-exponent (der-integer-value e))
	 (p (der-integer-value p))
	 (q (der-integer-value q))
	 (dP (der-integer-value dP))
	 (dQ (der-integer-value dQ))
	 (qP (der-integer-value qP)))))))
(define (rsa-private-key-exporter rsa-key)
  ;; As far as I know, RSA CRT key is the only exportable one
  ;; or defined on PKCS / RFC
  (unless (rsa-crt-private-key? rsa-key)
    (springkussen-assertion-violation 'rsa-private-key-exporter
				      "RSA CRT private key is required"))
  (asn1-object->bytevector
   (der-sequence
    (make-der-integer 0)
    (make-der-integer (rsa-private-key-modulus rsa-key))
    (make-der-integer (rsa-crt-private-key-public-exponent rsa-key))
    (make-der-integer (rsa-private-key-private-exponent rsa-key))
    (make-der-integer (rsa-crt-private-key-p rsa-key))
    (make-der-integer (rsa-crt-private-key-q rsa-key))
    (make-der-integer (rsa-crt-private-key-dP rsa-key))
    (make-der-integer (rsa-crt-private-key-dQ rsa-key))
    (make-der-integer (rsa-crt-private-key-qP rsa-key)))))
(define *rsa-private-key-operation*
  (make-asymmetric-key-operation rsa-private-key-importer
				 rsa-private-key-exporter))

)
