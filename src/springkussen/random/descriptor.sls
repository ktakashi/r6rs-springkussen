;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/random/descriptor.sls - Random descriptor
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
(library (springkussen random descriptor)
    (export random-descriptor? random-descriptor-builder

	    random-descriptor-name
	    random-descriptor-export-size

	    random-descriptor:start
	    random-descriptor:add-entropy!
	    random-descriptor:ready!
	    random-descriptor:read!
	    random-descriptor:done!
	    random-descriptor:import!
	    random-descriptor:export!

	    ;; For algorithm implementations
	    prng-state? (rename (prng-state <prng-state>))
	    prng-state-ready?
	    prng-state-ready?-set!
	    )
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen misc record))

(define-record-type random-descriptor
  (fields name
	  export-size
	  starter
	  entropy-updater
	  initializer
	  reader
	  finalizer
	  importer
	  exporter))

(define-syntax random-descriptor-builder
  (make-record-builder random-descriptor))

(define-record-type prng-state
  (fields (mutable ready?))
  (protocol (lambda (p) (lambda () (p #f)))))

(define (check who d)
  (unless (random-descriptor? d)
    (springkussen-assertion-violation who "Random descriptor required" d)))

(define (random-descriptor:start d)
  (check 'random-descriptor:start d)
  ((random-descriptor-starter d)))
				      
(define random-descriptor:add-entropy!
  (case-lambda
   ((d st in) (random-descriptor:add-entropy! d st in 0 (bytevector-length in)))
   ((d st in s)
    (random-descriptor:add-entropy! d st in s (bytevector-length in)))
   ((d st in s e)
    (check 'random-descriptor:add-entropy! d)
    ((random-descriptor-entropy-updater d) st in s e))))
    
(define (random-descriptor:ready! d st)
  (check 'random-descriptor:ready! d)
  ((random-descriptor-initializer d) st))

(define random-descriptor:read!
  (case-lambda
   ((d st bv) (random-descriptor:read! d st bv 0 (bytevector-length bv)))
   ((d st bv s)
    (random-descriptor:read! d st bv s (- (bytevector-length bv) s)))
   ((d st bv s len)
    (check 'random-descriptor:read! d)
    (unless (prng-state-ready? st)
      (springkussen-assertion-violation 'random-descriptor:read!
					  "PRNG is not ready yet"))
    (let ((l (bytevector-length bv)))
      (when (> len (- l s))
	(springkussen-assertion-violation 'random-descriptor:read!
					  "Not enough space to store")))
    ((random-descriptor-reader d) st bv s len))))

(define (random-descriptor:done! d st)
  (check 'random-descriptor:done! d)
  ((random-descriptor-finalizer d) st))

(define random-descriptor:import!
  (case-lambda
   ((d st in) (random-descriptor:import! d st in 0 (bytevector-length in)))
   ((d st in s)
    (random-descriptor:import! d st in s (- (bytevector-length in) s)))
   ((d st in s len)
    (check 'random-descriptor:import! d)
    (let ((l (bytevector-length in)))
      (when (> len (- l s))
	(springkussen-assertion-violation 'random-descriptor:import!
					  "Input state out of range")))
    ((random-descriptor-importer d) st in s len))))

(define random-descriptor:export!
  (case-lambda
   ((d st bv) (random-descriptor:export! d st bv 0))
   ((d st bv s)
    (check 'random-descriptor:export! d)
    (let ((size (random-descriptor-export-size d))
	  (l (bytevector-length bv)))
      (when (< (- l s) size)
	(springkussen-assertion-violation 'random-descriptor:export!
					  "Not enough space to store"))
      ((random-descriptor-exporter d) st bv s)))))

)

