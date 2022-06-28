;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/digest/md5.sls - MD5 operations
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

;; This algorithms is supported only for backward compatibility
;; It is users' responsibility not to use this algorithms

#!r6rs
(library (springkussen digest md5)
    (export md5-descriptor)
    (import (rnrs)
	    (springkussen digest descriptor)
	    (springkussen conditions)
	    (springkussen misc bitwise))

(define-record-type md5
  (parent <block-digest-state>)
  (protocol (lambda (n)
	      (lambda ()
		((n 64 (vector #x67452301
			       #xefcdab89
			       #x98badcfe
			       #x10325476)))))))

(define worder
  #vu8(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 
       1 6 11 0 5 10 15 4 9 14 3 8 13 2 7 12 
       5 8 11 14 1 4 7 10 13 0 3 6 9 12 15 2 
       0 7 14 5 12 3 10 1 8 15 6 13 4 11 2 9))
(define rorder
  #vu8(7 12 17 22 7 12 17 22 7 12 17 22 7 12 17 22 
       5 9 14 20 5 9 14 20 5 9 14 20 5 9 14 20 
       4 11 16 23 4 11 16 23 4 11 16 23 4 11 16 23 
       6 10 15 21 6 10 15 21 6 10 15 21 6 10 15 21))
(define korder
  '#(#xd76aa478 #xe8c7b756 #x242070db #xc1bdceee
     #xf57c0faf #x4787c62a #xa8304613 #xfd469501
     #x698098d8 #x8b44f7af #xffff5bb1 #x895cd7be
     #x6b901122 #xfd987193 #xa679438e #x49b40821

     #xf61e2562 #xc040b340 #x265e5a51 #xe9b6c7aa
     #xd62f105d #x02441453 #xd8a1e681 #xe7d3fbc8
     #x21e1cde6 #xc33707d6 #xf4d50d87 #x455a14ed
     #xa9e3e905 #xfcefa3f8 #x676f02d9 #x8d2a4c8a

     #xfffa3942 #x8771f681 #x6d9d6122 #xfde5380c
     #xa4beea44 #x4bdecfa9 #xf6bb4b60 #xbebfbc70
     #x289b7ec6 #xeaa127fa #xd4ef3085 #x04881d05
     #xd9d4d039 #xe6db99e5 #x1fa27cf8 #xc4ac5665

     #xf4292244 #x432aff97 #xab9423a7 #xfc93a039
     #x655b59c3 #x8f0ccc92 #xffeff47d #x85845dd1
     #x6fa87e4f #xfe2ce6e0 #xa3014314 #x4e0811a1
     #xf7537e82 #xbd3af235 #x2ad7d2bb #xeb86d391))

(define (F x y z) (bitwise-xor z (bitwise-and x (bitwise-xor y z))))
(define (G x y z) (bitwise-xor y (bitwise-and z (bitwise-xor y x))))
(define (H x y z) (bitwise-xor x y z))
(define (I x y z) (bitwise-xor y (bitwise-ior x (bitwise-not z))))
(define (make-FF fn)
  (lambda (a b c d M s t)
    (let ((a (+ a (fn b c d) M t)))      
      (+ (rolc a s) b))))
(define FF (make-FF F))
(define GG (make-FF G))
(define HH (make-FF H))
(define II (make-FF I))

(define (md5-compress md5 buffer start)
  (define (rotate W a b c d fun s e)
    (let loop ((i s) (a a) (b b) (c c) (d d))
      (if (= i e)
	  (values a b c d)
	  (let ((a* (fun a b c d
			 (vector-ref W (bytevector-u8-ref worder i))
			 (bytevector-u8-ref rorder i)
			 (vector-ref korder i))))
	    (loop (+ i 1) d a* b c)))))
  
  (define W (let ((w (make-vector 16)))
	      (do ((i 0 (+ i 1)))
		  ((= i 16) w)
		(vector-set! w i (load32l buffer (+ start (* i 4)))))))
  (define state (block-digest-state-state md5))
  (let ((a (vector-ref state 0))
	(b (vector-ref state 1))
	(c (vector-ref state 2))
	(d (vector-ref state 3)))
    (let*-values (((a b c d) (rotate W a b c d FF  0 16))
		  ((a b c d) (rotate W a b c d GG 16 32))
		  ((a b c d) (rotate W a b c d HH 32 48))
		  ((a b c d) (rotate W a b c d II 48 64)))
      (vector-set! state 0 (+ (vector-ref state 0) a))
      (vector-set! state 1 (+ (vector-ref state 1) b))
      (vector-set! state 2 (+ (vector-ref state 2) c))
      (vector-set! state 3 (+ (vector-ref state 3) d)))))

(define md5-process (make-block-digest-processor md5-compress 64))

(define md5-done
  (make-block-digest-finalizer md5-compress 64 store32l 16 'little))

(define md5-descriptor
  (digest-descriptor-builder
   (name "MD5")
   (digest-size 16)
   (oid "1.2.840.113549.2.5")
   (initializer make-md5)
   (processor md5-process)
   (finalizer md5-done)))

)
