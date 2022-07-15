;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/signature/ecdsa.sls - ECDSA Signer/Verifier
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
(library (springkussen signature ecdsa)
    (export ecdsa-signer-descriptor
	    ecdsa-verifier-descriptor

	    make-random-k-generator

	    ecdsa-private-key?
	    ecdsa-private-key-d ecdsa-private-key-ec-parameter
	    ecdsa-private-key-public-key

	    ecdsa-public-key?
	    ecdsa-public-key-Q
	    ecdsa-public-key-ec-parameter

	    ecdsa-signature-encode-type
	    make-ecdsa-encode-parameter ecdsa-encode-parameter?
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
	    sect113r1)
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen conditions)
	    (springkussen digest)
	    (springkussen math ec)
	    (springkussen math modular)
	    (springkussen misc bytevectors)
	    (springkussen random)
	    (springkussen signature descriptor)
	    (springkussen signature ecdsa key)
	    (springkussen signature parameters))

(define-enumeration ecdsa-signature-encode-type (der none)
  ecdsa-signature-encode-types)

(define-signature-parameter <ecdsa-encode-parameter>
  make-ecdsa-encode-parameter ecdsa-encode-parameter?
  (encode-type signature-parameter-encode-type))

;; Maybe better to move somewhere, as this can be used for DSA as well.
(define (make-random-k-generator prng)
  (define (read-random-bits! prng bv)
    (bytevector-fill! bv 0)
    (random-generator:read-random-bytes! prng bv)
    (bytevector->uinteger bv (endianness big)))
  (lambda (n d)
    (let* ((nbits (bitwise-length n))
	   (bytes (div nbits 8))
	   (bv (make-bytevector bytes 0)))
      (do ((r (read-random-bits! prng bv) (read-random-bits! prng bv)))
	  ((and (not (zero? r)) (< r n)) r)))))

(define-signature-parameter <k-generator-parameter>
  make-k-generator-parameter k-generator-parameter?
  (k-generator signature-parameter-k-generator))
(define default-k-generator (make-random-k-generator default-random-generator))

(define-record-type ecdsa-state
  (fields key
	  md
	  digester
	  encode-type))

(define-record-type ecdsa-signer-state
  (parent ecdsa-state)
  (fields k-generator))

(define (ecdsa-sign-init key param)
  (unless (ecdsa-private-key? key)
    (springkussen-assertion-violation 'signer-init
				      "Signer requires private key"))
  (let* ((md (signature-parameter-md param *digest:sha256*))
	 (encode-type (signature-parameter-encode-type param 'none))
	 (k-generator
	  (signature-parameter-k-generator param default-k-generator))
	 (digester (make-digester md)))
    (digester:init! digester)
    (make-ecdsa-signer-state key md digester encode-type k-generator)))

(define (ecdsa-sign-process state bv start end)
  (digester:process! (ecdsa-state-digester state) bv start end))

(define (ecdsa-sign-done state)
  (define (compute-r k-generator ec n d)
    (define G (ec-parameter-g ec))
    (define curve (ec-parameter-curve ec))
    (let loop ()
      (let* ((k (k-generator n d))
	     (p (ec-point-mul curve G k))
	     (r (mod (ec-point-x p) n)))
	(if (zero? r)
	    (loop)
	    (values r k)))))
  (define (compute-s r k e d n) (mod (* (mod-inverse k n) (+ e (* d r))) n))

  (define digester (ecdsa-state-digester state))
  (define key (ecdsa-state-key state))
  (define ec-param (ecdsa-private-key-ec-parameter key))
  (define n (ec-parameter-n ec-param))
  (define encode-type (ecdsa-state-encode-type state))
  (define k-generator (ecdsa-signer-state-k-generator state))
  (let ((d (ecdsa-private-key-d key))
	(e (compute-e n (digester:done digester))))
    (let loop ()
      (let-values (((r k) (compute-r k-generator ec-param n d)))
	(let ((s (compute-s r k e d n)))
	  (cond ((zero? s) (loop))
		((eq? encode-type 'der)
		 (asn1-object->bytevector
		  (der-sequence (make-der-integer r) (make-der-integer s))))
		(else
		 (let ((size (ceiling (/ (bitwise-length n) 8))))
		   (bytevector-append
		    (uinteger->bytevector r (endianness big) size)
		    (uinteger->bytevector s (endianness big) size))))))))))

(define ecdsa-signer-descriptor
  (signer-descriptor-builder
   (name "ECDSA")
   (initializer ecdsa-sign-init)
   (processor ecdsa-sign-process)
   (finalizer ecdsa-sign-done)))

(define (ecdsa-verify-init key param)
  (unless (ecdsa-public-key? key)
    (springkussen-assertion-violation 'verifier-init
				      "Verifier requries public key"))
  (let* ((md (signature-parameter-md param *digest:sha256*))
	 (encode-type (signature-parameter-encode-type param 'none))
	 (digester (make-digester md)))
    (digester:init! digester)
    (make-ecdsa-state key md digester encode-type)))

(define ecdsa-verify-process ecdsa-sign-process) ;; reuse

(define (ecdsa-verify-done state S)
  (define (parse-r&s encode-type S n)
    (define (parse-raw S)
      (let ((size (ceiling (/ (bitwise-length n) 8))))
	(let-values (((r s) (bytevector-split-at* S size)))
	  (values (bytevector->uinteger r (endianness big))
		  (bytevector->uinteger s (endianness big))))))
    (if (eq? encode-type 'der)
	(let ((r&s (bytevector->asn1-object S)))
	  (if (and (der-sequence? r&s)
		   (= (length (asn1-collection-elements r&s)) 2)
		   (for-all der-integer? (asn1-collection-elements r&s)))
	      (let ((e (asn1-collection-elements r&s)))
		(values (der-integer-value (car e))
			(der-integer-value (cadr e))))
	       ;; dummy, so that it can fail during the comparison
	      (parse-raw S)))
	(parse-raw S)))
    
  (define digester (ecdsa-state-digester state))
  (define key (ecdsa-state-key state))
  (define ec-param (ecdsa-public-key-ec-parameter key))
  (define n (ec-parameter-n ec-param))
  (define encode-type (ecdsa-state-encode-type state))
  
  (let ((e (compute-e n (digester:done digester))))
    (let-values (((r s) (parse-r&s encode-type S n)))
      (let* ((w (mod-inverse s n))
	     (u1 (mod (* e w) n))
	     (u2 (mod (* r w) n))
	     (G (ec-parameter-g ec-param))
	     (Q (ecdsa-public-key-Q key))
	     (curve (ec-parameter-curve ec-param)))
	;; it's a bit of oracle attack capability, but not sure
	;; how we should prevent
	(and (not (or (< r 1) (< n r)	;; r in range [1, n-1]
		      (< s 1) (< n s)))	;; s in range [1, n-1]
	     (let ((point (ec-point-add curve
					(ec-point-mul curve G u1)
					(ec-point-mul curve Q u2))))
	       (= (mod (ec-point-x point) n) (mod r n))))))))

(define ecdsa-verifier-descriptor
  (verifier-descriptor-builder
   (name "ECDSA")
   (initializer ecdsa-verify-init)
   (processor ecdsa-verify-process)
   (finalizer ecdsa-verify-done)))

(define (compute-e n M)
  (let ((len (bitwise-length n))
	(M-bits (* (bytevector-length M) 8)))
    (let ((e (bytevector->uinteger M (endianness big))))
      (if (< len M-bits)
	  (bitwise-arithmetic-shift-right e (- M-bits len))
	  e))))

)
