;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/random.sls - Secure Random generator
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
(library (springkussen random)
    (export random-generator?
	    fortuna-random-generator
	    (rename (fortuna-random-generator default-random-generator))

	    random-generator:read-random-bytes!
	    random-generator:read-random-bytes

	    random-generator:random
	    )
    (import (rnrs)
	    (springkussen random descriptor)
	    (springkussen random fortuna)
	    (springkussen random system)
	    (springkussen conditions)
	    (springkussen misc bytevectors))

(define-record-type random-generator
  (fields descriptor
	  state)
  (protocol (lambda (p)
	      (lambda (descriptor)
		(let ((state (random-descriptor:start descriptor))
		      (bv (make-bytevector 64)))
		  (read-system-random! bv)
		  (random-descriptor:add-entropy! descriptor state bv)
		  (random-descriptor:ready! descriptor state)
		  (p descriptor state))))))

(define fortuna-random-generator (make-random-generator fortuna-descriptor))

(define random-generator:read-random-bytes!
  (case-lambda
   ((prng bv) (random-generator:read-random-bytes! prng bv 0))
   ((prng bv s)
    (random-generator:read-random-bytes! prng bv s
					 (- (bytevector-length bv) s)))
   ((prng bv s len)
    (random-descriptor:read! (random-generator-descriptor prng)
			     (random-generator-state prng)
			     bv s len))))

(define (random-generator:read-random-bytes prng len)
  (let ((bv (make-bytevector len)))
    (random-generator:read-random-bytes! prng bv 0 len)
    bv))

(define random-generator:random
  (case-lambda
   ((prng size) (random-generator:random prng size #f))
   ((prng size read-size)
    (define rsize (or read-size (ceiling (/ (bitwise-length size) 8))))
    (let* ((bv (random-generator:read-random-bytes prng rsize))
	   (i (bytevector->uinteger bv (endianness big))))
      (if (>= i size)
	  (mod i size)
	  i)))))
)

