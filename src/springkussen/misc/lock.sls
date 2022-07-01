;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/misc/lock.sls - Mutex
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

;; Vanilla implementation of lock, using SRFI-18 or dummy
#!r6rs
(library (springkussen misc lock)
    (export (rename (make-mutex make-lock))
	    with-lock)
    (import (rnrs)
	    (springkussen misc eval-binding))

(define make-mutex (binding (srfi :18) make-mutex (lambda () (list 'dummy))))
(define mutex-lock!  (binding (srfi :18) mutex-lock! (lambda (m) m)))
(define mutex-unlock!  (binding (srfi :18) mutex-unlock! (lambda (m) m)))
  
(define-syntax with-lock
  (syntax-rules ()
    ((_ lock body0 body* ...)
     (let ((m lock))
       (define (thunk) body0 body* ...)
       (guard (e (else (mutex-unlock! m) (raise e)))
	 (mutex-lock! m)
	 (let ((r (thunk)))
	   (mutex-unlock! m)
	   r))))))

)

