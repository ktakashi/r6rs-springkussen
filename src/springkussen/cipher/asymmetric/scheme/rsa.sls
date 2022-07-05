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
	    (springkussen conditions)
	    (springkussen cipher asymmetric key)
	    (springkussen cipher asymmetric scheme descriptor)
	    (springkussen math modular)
	    (springkussen misc bytevectors)
	    (springkussen misc record))


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
		((n m d) p q
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

;; minor helper
(define-syntax align-size
  (syntax-rules (bit)
    ((_ (bit n))
     (div (+ n 7) 8))
    ((_ n)
     (let ((bitlen (bitwise-length n)))
       (div (+ bitlen 7) 8)))))

(define rsa-descriptor
  (asymmetric-scheme-descriptor-builder
   (name "RSA")
   (block-sizer rsa-block-size-retriever)
   (setupper rsa-setup)
   (encryptor rsa-encrypt)
   (decryptor rsa-decrypt)
   (finalizer rsa-finalize)))


)
