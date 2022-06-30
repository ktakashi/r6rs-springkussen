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
    (export bytevector-xor bytevector-xor!
	    bytevector->uinteger)
    (import (rnrs))

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


)

