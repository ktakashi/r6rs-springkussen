;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/mac/descriptor.sls - MAC descriptor
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
(library (springkussen mac descriptor)
    (export mac-descriptor? mac-descriptor-builder
	    mac-descriptor-name
	    
	    mac-descriptor:init
	    mac-descriptor:mac-size
	    mac-descriptor:process!
	    mac-descriptor:done!

	    mac-parameter? make-mac-parameter
	    make-define-mac-parameter
	    )
    (import (rnrs)
	    (springkussen misc record))

(define-record-type mac-descriptor
  (fields name
	  mac-sizer
	  starter
	  processor
	  finalizer))
(define-syntax mac-descriptor-builder
  (make-record-builder mac-descriptor))

(define-compositable-record-type mac-parameter)

(define (mac-descriptor:init descriptor param)
  ((mac-descriptor-starter descriptor) param))

(define (mac-descriptor:mac-size descriptor state)
  ((mac-descriptor-mac-sizer descriptor) state))

(define mac-descriptor:process!
  (case-lambda
   ((descriptor state bv)
    (mac-descriptor:process! descriptor state bv 0 (bytevector-length bv)))
   ((descriptor state bv start)
    (mac-descriptor:process! descriptor state bv start (bytevector-length bv)))
   ((descriptor state bv start end)
    ((mac-descriptor-processor descriptor) state bv start end))))

(define mac-descriptor:done!
  (case-lambda
   ((descriptor state bv)
    (mac-descriptor:done! descriptor state bv 0))
   ((descriptor state bv start)
    (mac-descriptor:done! descriptor state bv start
			  (- (bytevector-length bv) start)))
   ((descriptor state bv start len)
    ((mac-descriptor-finalizer descriptor) state bv start len))))

)
