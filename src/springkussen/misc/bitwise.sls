;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/misc/bitwise.sls - Misc bitwise operations
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
;; The implementation is from aeolus, which is written by me :)
(library (springkussen misc bitwise)
    (export byte bswap 
	    rol ror rolc rorc ror64 ror64c
	    load32l load32h load64l load64h
	    store32l store32h store64h)
    (import (rnrs))

(define-syntax byte
  (syntax-rules ()
    ((_ x i)
     (let ((n (* 8 i)))
       (bitwise-and #xff (bitwise-arithmetic-shift x (- n)))))))

(define (bswap x)
  (bitwise-ior (bitwise-and (bitwise-arithmetic-shift x -24) #x000000FF)
	       (bitwise-and (bitwise-arithmetic-shift x  24) #xFF000000)
	       (bitwise-and (bitwise-arithmetic-shift x  -8) #x0000FF00)
	       (bitwise-and (bitwise-arithmetic-shift x   8) #x00FF0000)))

(define (rol x y)
  (define y31 (bitwise-and y 31))
  (let ((n1 (bitwise-arithmetic-shift x y31))
	(n2 (bitwise-and (bitwise-arithmetic-shift-right
			  (bitwise-and x #xFFFFFFFF)
			  (bitwise-and (- 32 y31) 31)))))
    (bitwise-and (bitwise-ior n1 n2) #xFFFFFFFF)))
(define (ror x y)
  (define y31 (bitwise-and y 31))
  (let ((n1 (bitwise-arithmetic-shift (bitwise-and x #xFFFFFFFF) (- y31)))
	(n2 (bitwise-arithmetic-shift x (bitwise-and (- 32 y31) 31))))
    (bitwise-and (bitwise-ior n1 n2) #xFFFFFFFF)))
(define rolc rol)
(define rorc ror)

(define (rol64 x y)
  (bitwise-and
   (bitwise-ior (bitwise-arithmetic-shift x (bitwise-and y 63))
		(bitwise-arithmetic-shift-right
		 (bitwise-and x #xFFFFFFFFFFFFFFFF)
		 (bitwise-and (- 64 (bitwise-and y 63)) 63)))
   #xFFFFFFFFFFFFFFFF))
(define (ror64 x y)
  (let ((w (bitwise-arithmetic-shift-right (bitwise-and x #xFFFFFFFFFFFFFFFF)
					   (bitwise-and y 63)))
	(z (bitwise-arithmetic-shift x (bitwise-and (- 64 (bitwise-and y 63))
						    63))))
    (bitwise-and (bitwise-ior w z) #xFFFFFFFFFFFFFFFF)))
(define rol64c rol64)
(define ror64c ror64)

(define (load32l bv start)
  (bytevector-u32-ref bv start (endianness little)))
(define (load32h bv start)
  (bytevector-u32-ref bv start (endianness big)))
(define (load64l bv start)
  (bytevector-u64-ref bv start (endianness little)))
(define (load64h bv start)
  (bytevector-u64-ref bv start (endianness big)))
(define (store32l bv start v)
  (bytevector-u32-set! bv start v (endianness little)))
(define (store32h bv start v)
  (bytevector-u32-set! bv start v (endianness big)))
(define (store64h bv start v)
  (bytevector-u64-set! bv start v (endianness big)))
)

