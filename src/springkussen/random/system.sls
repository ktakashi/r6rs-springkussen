;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/random/system.sls - System random
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
(library (springkussen random system)
    (export read-system-random!)
    (import (rnrs))

(define read-system-random! 
  (case-lambda
   ((bv) (read-system-random! bv 0 (bytevector-length bv)))
   ((bv s) (read-system-random! bv s (- (bytevector-length bv) s)))
   ((bv s len) (try-read-system-random bv s len))))

(define (try-read-system-random bv s len)
  (define (try-read-file file bv s len)
    (guard (e ((i/o-file-does-not-exist-error? e) #f)
	      ;; Something else
	      (else (raise e)))
      (call-with-port (open-file-input-port file)
	(lambda (in) (get-bytevector-n! in bv s len)))))
  ;; let's try one by one...
  (cond ((try-read-file "/dev/urandom" bv s len))
	((try-read-file "/dev/random" bv s len))
	(else
	 ;; probably Windows?
	 ;; FIXME please implement here
	 (raise (condition (make-implementation-restriction-violation)
			   (make-who-condition 'read-system-random!)
			   (make-message-condition "No random device file"))))))
)

