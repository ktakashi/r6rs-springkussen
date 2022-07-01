;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/misc/lock.chezscheme.sls - Mutex for Chez Scheme
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
(library (springkussen misc lock)
    (export make-lock with-lock)
    (import (chezscheme)
	    (springkussen misc eval-binding))

;; for some reason, thread related procedure isn't available on my
;; environment (Mac), so this means, we need to do the same trick as
;; vanilla...
(define make-lock (binding (chezscheme) make-mutex (lambda () (list 'dummy))))
(define mutex-acquire (binding (chezscheme) mutex-acquire (lambda (m b) m)))
(define mutex-release  (binding (srfi :18) mutex-release (lambda (m) m)))
  
(define-syntax with-lock
  (syntax-rules ()
    ((_ lock body0 body* ...)
     (let ((m lock))
       (define (thunk) body0 body* ...)
       (guard (e (else (mutex-release m) (raise e)))
	 (mutex-acquire m #t)
	 (let ((r (thunk)))
	   (mutex-release m)
	   r))))))


)

