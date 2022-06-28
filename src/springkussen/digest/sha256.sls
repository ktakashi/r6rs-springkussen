;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/digest/sha256.sls - SHA-256 / SHA-224 operations
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
(library (springkussen digest sha256)
    (export sha256-descriptor
	    sha224-descriptor)
    (import (rnrs)
	    (springkussen digest descriptor)
	    (springkussen conditions)
	    (springkussen misc bitwise))

(define-record-type sha256
  (parent <block-digest-state>)
  (protocol (lambda (n)
	      (lambda ()
		((n 64 (vector #x6A09E667
			       #xBB67AE85
			       #x3C6EF372
			       #xA54FF53A
			       #x510E527F
			       #x9B05688C
			       #x1F83D9AB
			       #x5BE0CD19)))))))

(define-record-type sha224
  (parent <block-digest-state>)
  (protocol (lambda (n)
	      (lambda ()
		((n 64 (vector #xc1059ed8
			       #x367cd507
			       #x3070dd17
			       #xf70e5939
			       #xffc00b31
			       #x68581511
			       #x64f98fa7
			       #xbefa4fa4)))))))

(define K '#(
    #x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b
    #x59f111f1 #x923f82a4 #xab1c5ed5 #xd807aa98 #x12835b01
    #x243185be #x550c7dc3 #x72be5d74 #x80deb1fe #x9bdc06a7
    #xc19bf174 #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
    #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da #x983e5152
    #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147
    #x06ca6351 #x14292967 #x27b70a85 #x2e1b2138 #x4d2c6dfc
    #x53380d13 #x650a7354 #x766a0abb #x81c2c92e #x92722c85
    #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3 #xd192e819
    #xd6990624 #xf40e3585 #x106aa070 #x19a4c116 #x1e376c08
    #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a #x5b9cca4f
    #x682e6ff3 #x748f82ee #x78a5636f #x84c87814 #x8cc70208
    #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2
    ))
(define (sha256-compress sha256 buffer start)
  (define (ch x y z) (bitwise-xor z (bitwise-and x (bitwise-xor y z))))
  (define (maj x y z) (bitwise-ior (bitwise-and (bitwise-ior x y) z)
				   (bitwise-and x y)))
  (define S rorc)
  (define (R x n) (bitwise-arithmetic-shift-right (bitwise-and x #xFFFFFFFF) n))
  (define (sigma0 x) (bitwise-xor (S x 2) (S x 13) (S x 22)))
  (define (sigma1 x) (bitwise-xor (S x 6) (S x 11) (S x 25)))
  (define (gamma0 x) (bitwise-xor (S x 7) (S x 18) (R x 3)))
  (define (gamma1 x) (bitwise-xor (S x 17) (S x 19) (R x 10)))
  (define (setup-w buffer)
    (define (fill w)
      (do ((i 16 (+ i 1)))
	  ((= i 64) w)
	(let ((v (+ (gamma1 (vector-ref w (- i 2)))
		    (vector-ref w (- i 7))
		    (gamma0 (vector-ref w (- i 15)))
		    (vector-ref w (- i 16)))))
	  (vector-set! w i v))))
    (let ((w (make-vector 64 0)))
      (do ((i 0 (+ i 1)))
	  ((= i 16) (fill w))
	(vector-set! w i (load32h buffer (+ start (* i 4)))))))
  (define (rnd a b c d e f g h i)
    (let ((t0 (+ h (sigma1 e) (ch e f g) (vector-ref K i) (vector-ref W i)))
	  (t1 (+ (sigma0 a) (maj a b c))))
      (values a b c (+ d t0) e f g (+ t0 t1))))
  
  (define (feedback state S0 S1 S2 S3 S4 S5 S6 S7)
    (vector-set! state 0 (+ (vector-ref state 0) S0))
    (vector-set! state 1 (+ (vector-ref state 1) S1))
    (vector-set! state 2 (+ (vector-ref state 2) S2))
    (vector-set! state 3 (+ (vector-ref state 3) S3))
    (vector-set! state 4 (+ (vector-ref state 4) S4))
    (vector-set! state 5 (+ (vector-ref state 5) S5))
    (vector-set! state 6 (+ (vector-ref state 6) S6))
    (vector-set! state 7 (+ (vector-ref state 7) S7)))

  (define state (block-digest-state-state sha256))
  (define W (setup-w buffer))

  (let loop ((i 0)
	     (S0 (vector-ref state 0))
	     (S1 (vector-ref state 1))
	     (S2 (vector-ref state 2))
	     (S3 (vector-ref state 3))
	     (S4 (vector-ref state 4))
	     (S5 (vector-ref state 5))
	     (S6 (vector-ref state 6))
	     (S7 (vector-ref state 7)))
    (if (= i 64)
	(feedback state S0 S1 S2 S3 S4 S5 S6 S7)
	(let-values (((S0 S1 S2 S3 S4 S5 S6 S7)
		      (rnd S0 S1 S2 S3 S4 S5 S6 S7 i)))
	  (loop (+ i 1) S7 S0 S1 S2 S3 S4 S5 S6)))))

(define sha256-process (make-block-digest-processor sha256-compress 64))

(define sha256-done
  (make-block-digest-finalizer sha256-compress 64 store32h 32))

(define sha256-descriptor
  (digest-descriptor-builder
   (name "SHA-256")
   (digest-size 32)
   (oid "2.16.840.1.101.3.4.2.1")
   (initializer make-sha256)
   (processor sha256-process)
   (finalizer sha256-done)))

(define sha256-done
  (make-block-digest-finalizer sha256-compress 64 store32h 28))

(define sha224-descriptor
  (digest-descriptor-builder
   (name "SHA-224")
   (digest-size 28)
   (oid "2.16.840.1.101.3.4.2.4")
   (initializer make-sha224)
   (processor sha256-process)
   (finalizer sha256-done)))

)
