;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/misc/bytevectors.sls - Misc bytevector operations
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
(library (springkussen misc bytevectors)
    (export bytevector-append bytevector-xor bytevector-xor!
	    bytevector->uinteger uinteger->bytevector
	    bytevector-safe=?)
    (import (rnrs))

(define (bytevector-append . bv*)
  (define size
    (fold-left (lambda (acc bv) (+ acc (bytevector-length bv))) 0 bv*))
  (do ((r (make-bytevector size)) (bv* bv* (cdr bv*))
       (start 0 (+ start (bytevector-length (car bv*)))))
      ((null? bv*) r)
    (bytevector-copy! (car bv*) 0 r start (bytevector-length (car bv*)))))

  
(define (bytevector-xor! bv0 start0 bv1 start1 size)
  (do ((i 0 (+ i 1)))
      ((= i size) bv0)
    (let ((p0 (+ start0 i))
	  (p1 (+ start1 i)))
      (bytevector-u8-set! bv0 p0
			  (bitwise-xor (bytevector-u8-ref bv0 p0)
				       (bytevector-u8-ref bv1 p1))))))

(define (bytevector-xor bv0 start0 bv1 start1 size)
  (bytevector-xor! (bytevector-copy bv0) start0 bv1 start1 size))

(define (bytevector->uinteger bv endian)
  (define size (bytevector-length bv))
  (case endian
    ((big)
     (do ((i 0 (+ i 1)) (r 0 (bitwise-ior (bitwise-arithmetic-shift r 8)
					  (bytevector-u8-ref bv i))))
	 ((= i size) r)))
    ((little)
     (do ((i (- size 1) (- i 1))
	  (r 0 (bitwise-ior (bitwise-arithmetic-shift r 8)
			    (bytevector-u8-ref bv i))))
	 ((< i 0) r)))
    (else
     (assertion-violation 'bytevector->uinteger "Unknown endian type" endian))))

(define uinteger->bytevector
  (case-lambda
   ((ui endian)
    (let* ((bitlen (bitwise-length ui))
	   (len (+ (div bitlen 8) (if (zero? (bitwise-and bitlen 7)) 0 1))))
      (uinteger->bytevector ui endian(if (zero? len) 1 len))))
   ((ui endian size)
    (let ((bv (make-bytevector size)))
      (do ((i 0 (+ i 1)))
	  ((= i size) bv)
	(let ((n (bitwise-and (bitwise-arithmetic-shift ui (* i -8)) #xFF))
	      (pos (case endian
		     ((big) (- size i 1))
		     ((little) i)
		     (else (assertion-violation 'uinteger->bytevector
						"Unknown endian" endian)))))
	  (bytevector-u8-set! bv pos n)))))))

(define (bytevector-safe=? bv1 bv2)
  (define l1 (bytevector-length bv1))
  (define l2 (bytevector-length bv2))
  (let loop ((i 0) (j 0) (ok? #t))
    (cond ((and (= i l1) (= j l2)) ok?)
	  ((and (< i l1) (< j l2))
	   (loop (+ i 1) (+ j 1)
		 (and ok? (= (bytevector-u8-ref bv1 i)
			     (bytevector-u8-ref bv2 j)))))
	  ((= i l1) (loop i (+ j 1) #f))
	  ((= j l2) (loop (+ i 1) j #f))
	  ;; This should never happen
	  (else #f))))

)

