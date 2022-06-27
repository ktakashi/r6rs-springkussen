;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/digest/descriptor.sls - Digest descriptor
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
(library (springkussen digest descriptor)
    (export digest-descriptor?
	    digest-descriptor-builder
	    digest-descriptor-digest-size
	    digest-descriptor-oid

	    digest-descriptor:digest ;; High level
	    digest-descriptor:init
	    digest-descriptor:process!
	    digest-descriptor:done!

	    digest-state? 
	    block-digest-state?
	    (rename (digest-state <digest-state>)
		    (block-digest-state <block-digest-state>))
	    block-digest-state-buffer
	    block-digest-state-count
	    block-digest-state-count-add!
	    block-digest-state-length
	    block-digest-state-length-add!
	    make-block-digest-processor
	    )
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen misc record))

(define-record-type digest-descriptor
  (fields digest-size		   ; Digest size in octets
	  oid			   ; Digest OID (#f if not registered)
	  initializer
	  processor
	  finalizer))

(define-syntax digest-descriptor-builder
  (make-record-builder digest-descriptor))

(define (digest-descriptor:digest descriptor bv)
  (let ((state (digest-descriptor:init descriptor))
	(out (make-bytevector (digest-descriptor-digest-size descriptor))))
    (digest-descriptor:process! descriptor state bv)
    (digest-descriptor:done! descriptor state out)
    out))

(define (digest-descriptor:init descriptor)
  ((digest-descriptor-initializer descriptor)))
(define digest-descriptor:process!
  (case-lambda
   ((descriptor state bv) (digest-descriptor:process! descriptor state bv 0))
   ((descriptor state bv start)
    (digest-descriptor:process! descriptor state bv start
				(bytevector-length bv)))
   ((descriptor state bv start end)
    ((digest-descriptor-processor descriptor) state bv start end))))
(define digest-descriptor:done!
  (case-lambda
   ((descriptor state out) (digest-descriptor:done! descriptor state out 0))
   ((descriptor state out start)
    ((digest-descriptor-finalizer descriptor) state out start))))

(define-record-type digest-state)

;; MD4 family styled digest
(define-record-type block-digest-state
  (fields buffer
	  (mutable count)
	  (mutable length))
  (protocol (lambda (p)
	      (lambda (n)
		(p (make-bytevector n 0) 0 0)))))

(define (block-digest-state-count-add! digest n)
  (let ((v (+ n (block-digest-state-count digest))))
    (block-digest-state-count-set! digest v)
    v))

(define (block-digest-state-length-add! digest nl)
  (let ((v (+ nl (block-digest-state-length digest))))
    (block-digest-state-length-set! digest v)
    v))

(define (make-block-digest-processor compress block)
  (define comp compress)
  (define block-size block)
  (define block-in-bits (* block-size 8))
  (define (update-count! digest count)
    (block-digest-state-count-set! digest count)
    digest)
  (define update-length! block-digest-state-length-add!)
  (lambda (digest in start end)
    (define buffer (block-digest-state-buffer digest))
    (define count (block-digest-state-count digest))
    (when (> count (bytevector-length buffer))
      (springkussen-assertion-violation 'digest-processor
					"Invalid argument" digest))
    (let loop ((c count) (inlen (- end start)) (start start))
      (if (<= inlen 0)
	  (update-count! digest c)
	  (cond ((and (zero? c) (>= inlen block-size))
		 (comp digest in start) ;; compress
		 (update-length! digest block-in-bits)
		 (loop 0 (- inlen block-size) (+ start block-size)))
		(else
		 (let ((n (min inlen (- block-size c))))
		   (bytevector-copy! in start buffer c n)
		   (cond ((= (+ c n) block-size)
			  (comp digest buffer 0)
			  (update-length! digest block-in-bits)
			  (loop 0 (- inlen n) (+ start n)))
			 (else
			  (loop (+ c n) (- inlen n) (+ start n)))))))))))

)
