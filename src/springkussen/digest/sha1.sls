;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/digest/sha1.sls - SHA-1 operations
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
(library (springkussen digest sha1)
    (export sha1-descriptor)
    (import (rnrs)
	    (springkussen digest descriptor)
	    (springkussen conditions)
	    (springkussen misc bitwise))

(define-record-type sha1
  (parent <block-digest-state>)
  (fields state)
  (protocol (lambda (n)
	      (lambda ()
		((n 64)
		 (vector #x67452301
			 #xefcdab89
			 #x98badcfe
			 #x10325476
			 #xc3d2e1f0))))))

(define (u32 v) (bitwise-and v #xFFFFFFFF))
(define (sha1-compress sha1 buffer start)
  (define (setup-w buffer start)
    (define (expand W)
      (do ((i 16 (+ i 1)))
	  ((= i 80) W)
	(let ((v (bitwise-xor (vector-ref W (- i 3))
			      (vector-ref W (- i 8))
			      (vector-ref W (- i 14))
			      (vector-ref W (- i 16)))))
	  (vector-set! W i (rol v 1)))))
    ;; Copy the state into 512 bits into W[0..15]
    (let ((W (make-vector 80)))
      (do ((i 0 (+ i 1)))
	  ((= i 16) (expand W))
	(vector-set! W i (load32h buffer (+ start (* i 4)))))))
  (define (f0 x y z) (bitwise-xor z (bitwise-and x (bitwise-xor y z))))
  (define (f1 x y z) (bitwise-xor x y z))
  (define (f2 x y z) (bitwise-ior (bitwise-and x y)
				  (bitwise-and z (bitwise-ior x y))))
  (define (f3 x y z) (bitwise-xor x y z))
  (define (make-ff fn magic)
    (lambda (W a b c d e i)
      (values (+ (rolc a 5) (fn b c d) e (vector-ref W i) magic) (rolc b 30))))
  (define ff0 (make-ff f0 #x5a827999))
  (define ff1 (make-ff f1 #x6ed9eba1))
  (define ff2 (make-ff f2 #x8f1bbcdc))
  (define ff3 (make-ff f3 #xca62c1d6))

  (define (do-compress W ff a b c d e start end)
    (let loop ((i start) (a a) (b b) (c c) (d d) (e e))
      (if (= i end)
	  (values a b c d e)
	  (let*-values (((e b) (ff W a b c d e    i  ))
			((d a) (ff W e a b c d (+ i 1)))
			((c e) (ff W d e a b c (+ i 2)))
			((b d) (ff W c d e a b (+ i 3)))
			((a c) (ff W b c d e a (+ i 4))))
	    (loop (+ i 5) a b c d e)))))
  (define state (sha1-state sha1))
  (let ((W (setup-w buffer start))
	(a (vector-ref state 0))
	(b (vector-ref state 1))
	(c (vector-ref state 2))
	(d (vector-ref state 3))
	(e (vector-ref state 4)))
    (let*-values (((a b c d e) (do-compress W ff0 a b c d e  0 20))
		  ((a b c d e) (do-compress W ff1 a b c d e 20 40))
		  ((a b c d e) (do-compress W ff2 a b c d e 40 60))
		  ((a b c d e) (do-compress W ff3 a b c d e 60 80)))
      (vector-set! state 0 (+ (vector-ref state 0) a))
      (vector-set! state 1 (+ (vector-ref state 1) b))
      (vector-set! state 2 (+ (vector-ref state 2) c))
      (vector-set! state 3 (+ (vector-ref state 3) d))
      (vector-set! state 4 (+ (vector-ref state 4) e)))))

(define sha1-process (make-block-digest-processor sha1-compress 64))

(define (sha1-done sha1 out pos)
  (define buffer (block-digest-state-buffer sha1))
  (define count (block-digest-state-count sha1))
  (define (check-compress buffer count)
    (if (> count 56)
	(do ((i count (+ i 1)))
	    ((= i 64) (sha1-compress sha1 buffer 0) 0)
	  (bytevector-u8-set! buffer i 0))
	count))
  (define (pad-zeros buffer count)
    (if (< count 56)
	(do ((i count (+ i 1)))
	    ((= i 56) i)
	  (bytevector-u8-set! buffer i 0))
	count))
  (when (> count (bytevector-length buffer))
    (springkussen-assertion-violation 'sha1-done "Invalid argument" sha1))
  (bytevector-u8-set! buffer count #x80) ;; append the 1 bit
  (let* ((len   (block-digest-state-length-add! sha1 (* count 8)))
	 (count (check-compress buffer (+ count 1)))
	 (count (pad-zeros buffer count))
	 (state (sha1-state sha1)))
    (store64h buffer 56 len)
    (sha1-compress sha1 buffer 0)
    (store32h out         0  (u32 (vector-ref state 0)))
    (store32h out (+ pos  4) (u32 (vector-ref state 1)))
    (store32h out (+ pos  8) (u32 (vector-ref state 2)))
    (store32h out (+ pos 12) (u32 (vector-ref state 3)))
    (store32h out (+ pos 16) (u32 (vector-ref state 4)))
    out))

(define sha1-descriptor
  (digest-descriptor-builder
   (digest-size 20)
   (oid "1.3.14.3.2.26")
   (initializer make-sha1)
   (processor sha1-process)
   (finalizer sha1-done)))

)
