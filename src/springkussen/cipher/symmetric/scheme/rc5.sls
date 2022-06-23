;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/symmetric/scheme/rc5.sls - RC5 operation
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
(library (springkussen cipher symmetric scheme rc5)
    (export rc5-descriptor)
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen cipher symmetric scheme descriptor)
	    (springkussen misc bitwise)
	    (springkussen misc vectors))


(define-record-type rc5-key
  ;; K = ulong32[50]
  (fields rounds K)
  (protocol (lambda (p)
	      (lambda (rounds)
		(p rounds (make-vector 50))))))

(define (u32 v) (bitwise-and #xFFFFFFFF v))
(define (rc5-setup key param-round)
  (define round (if (zero? param-round)
		    (symmetric-scheme-descriptor-default-round rc5-descriptor)
		    param-round))
  (define (copy-key key)
    (define keylen (bytevector-length key))
    (define L (make-vector 64))
    (let loop ((A 0) (i 0) (j 0))
      (if (= i keylen)
	  (let ((right (bitwise-and keylen 3)))
	    (if (zero? right)
		(values A L j)
		(let ((A (u32 (bitwise-arithmetic-shift A (* 8 (- 4 right))))))
		  (vector-set! L j (bswap A))
		  (values A L (+ j 1)))))
	  (let ((A (bitwise-ior (bitwise-arithmetic-shift A 8)
				(bytevector-u8-ref key i))))
	    (let ((i (+ i 1)))
	      (if (zero? (bitwise-and i 3))
		  (let ((x (bswap A)))
		    (vector-set! L j x)
		    (loop 0 i (+ j 1)))
		  (loop A i j)))))))
  (define (mix-buffer! S L t l)
    (define s (* 3 (max t l)))
    (let loop ((A 0) (B 0) (i 0) (j 0) (v 0))
      (unless (= v s)
	(let* ((A (rolc (+ (vector-ref S i) A B) 3))
	       (B (rol (+ (vector-ref L j) A B) (+ A B))))
	  (vector-set! S i A)
	  (vector-set! L j B)
	  (let ((i (+ i 1)) (j (+ j 1)))
	    (loop A B (if (= i t) 0 i) (if (= j l) 0 j) (+ v 1)))))))

  (unless (<= 12 round 24)
    (springkussen-assertion-violation 'setup "invalid round" round))
  (let* ((skey (make-rc5-key round))
	 (S (rc5-key-K skey)))
    (let-values (((A L j) (copy-key key)))
      (let ((t (* 2 (+ round 1))))
	(vector-copy! stab 0 S 0 t)
	(mix-buffer! S L t j)
	skey))))

(define xor bitwise-xor)
(define (rc5-encrypt pt ps ct cs key)
  (define rounds (rc5-key-rounds key))
  (define K (rc5-key-K key))
  (define A (u32 (+ (load32l pt ps)       (vector-ref K 0)))) ;; first word
  (define B (u32 (+ (load32l pt (+ ps 4)) (vector-ref K 1)))) ;; second word
  (define (store-ct! ct cs A B)
    (store32l ct cs A)
    (store32l ct (+ cs 4) B))

  (if (even? rounds)
      (let loop ((r 0) (A A) (B B) (ki 2))
	(if (= r rounds)
	    (store-ct! ct cs A B)
	    (let* ((A (u32 (+ (rol (xor A B) B) (vector-ref K ki))))
		   (B (u32 (+ (rol (xor B A) A) (vector-ref K (+ ki 1)))))
		   (A (u32 (+ (rol (xor A B) B) (vector-ref K (+ ki 2)))))
		   (B (u32 (+ (rol (xor B A) A) (vector-ref K (+ ki 3))))))
	      (loop (+ r 2) A B (+ ki 4)))))
      (let loop ((r 0) (A A) (B B) (ki 2))
	(if (= r rounds)
	    (store-ct! ct cs A B)
	    (let* ((A (u32 (+ (rol (xor A B) B) (vector-ref K ki))))
		   (B (u32 (+ (rol (xor B A) A) (vector-ref K (+ ki 1))))))
	      (loop (+ r 1) A B (+ ki 2))))))
  8)

(define (rc5-decrypt ct cs pt ps key)
  (define rounds (rc5-key-rounds key))
  (define K (rc5-key-K key))
  (define A (load32l ct cs)) ;; first word
  (define B (load32l ct (+ cs 4))) ;; second word
  (define ki (* rounds 2))
  (define (store-pt! pt ps A B)
    (store32l pt ps       (u32 (- A (vector-ref K 0))))
    (store32l pt (+ ps 4) (u32 (- B (vector-ref K 1)))))

  (if (even? rounds)
      (let loop ((r (- rounds 1)) (B B) (A A) (ki (- ki 2)))
	(if (< r 0)
	    (store-pt! pt ps A B)
	    (let* ((B (u32 (xor (ror (- B (vector-ref K (+ ki 3))) A) A)))
		   (A (u32 (xor (ror (- A (vector-ref K (+ ki 2))) B) B)))
		   (B (u32 (xor (ror (- B (vector-ref K (+ ki 1))) A) A)))
		   (A (u32 (xor (ror (- A (vector-ref K ki))       B) B))))
	      (loop (- r 2) B A (- ki 4)))))
      (let loop ((r (- rounds 1)) (B B) (A A) (ki (- ki 2)))
	(if (< r 0)
	    (store-pt! pt ps A B)
	    (let* ((B (u32 (xor (ror (- B (vector-ref K (+ ki 1))) A) A)))
		   (A (u32 (xor (ror (- A (vector-ref K ki))       B) B))))
	      (loop (- r 1) B A (- ki 2))))))
  8)

(define (rc5-done key) #t)

(define rc5-descriptor
  (symmetric-scheme-descriptor-builder
   (key-length* '(8 . 128))
   (block-size 8)
   (default-round 12)
   (setupper rc5-setup)
   (encryptor rc5-encrypt)
   (decryptor rc5-decrypt)
   (finalizer rc5-done)))

(define stab
  '#(
     #xb7e15163 #x5618cb1c #xf45044d5 #x9287be8e #x30bf3847 #xcef6b200
     #x6d2e2bb9 #x0b65a572 #xa99d1f2b #x47d498e4 #xe60c129d #x84438c56
     #x227b060f #xc0b27fc8 #x5ee9f981 #xfd21733a #x9b58ecf3 #x399066ac
     #xd7c7e065 #x75ff5a1e #x1436d3d7 #xb26e4d90 #x50a5c749 #xeedd4102
     #x8d14babb #x2b4c3474 #xc983ae2d #x67bb27e6 #x05f2a19f #xa42a1b58
     #x42619511 #xe0990eca #x7ed08883 #x1d08023c #xbb3f7bf5 #x5976f5ae
     #xf7ae6f67 #x95e5e920 #x341d62d9 #xd254dc92 #x708c564b #x0ec3d004
     #xacfb49bd #x4b32c376 #xe96a3d2f #x87a1b6e8 #x25d930a1 #xc410aa5a
     #x62482413 #x007f9dcc
     ))
)
