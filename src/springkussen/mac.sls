;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/mac.sls - MAC API
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
(library (springkussen mac)
    (export mac? make-mac
	    mac:generate-mac
	    mac:generate-mac!

	    mac:init!
	    mac:process!
	    mac:done!
	    mac:mac-size
	    mac:mac-oid
	    
	    mac-descriptor?
	    mac-descriptor-name
	    (rename (hmac-descriptor *mac:hmac*))

	    mac-parameter? make-mac-parameter
	    make-hmac-parameter hmac-parameter?
	    )
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen mac descriptor)
	    (springkussen mac hmac))

(define-record-type mac
  (fields (mutable state)
	  descriptor
	  parameter)
  (protocol (lambda (p)
	      (lambda (descriptor parameter)
		(unless (mac-descriptor? descriptor)
		  (springkussen-assertion-violation 'make-mac
		    "MAC descriptor required" descriptor))
		(unless (mac-parameter? parameter)
		  (springkussen-assertion-violation 'make-mac
		    "MAC parameter required" parameter))
		(p #f descriptor parameter)))))

(define mac:generate-mac
  (case-lambda
   ((mac bv) (mac:generate-mac mac bv #f))
   ((mac bv len)
    (let ((out (or (and (integer? len) (make-bytevector len))
		   (make-bytevector (mac:mac-size mac)))))
      (mac:generate-mac! mac bv out)))))
  
(define mac:generate-mac!
  (case-lambda
   ((mac bv out) (mac:generate-mac! mac bv out 0 (bytevector-length out)))
   ((mac bv out pos)
    (mac:generate-mac! mac bv out pos (- (bytevector-length out) pos)))
   ((mac bv out pos len)
    (mac:init! mac)
    (mac:process! mac bv)
    (mac:done! mac out pos len))))

(define (mac:init! mac)
  (unless (mac? mac)
    (springkussen-assertion-violation 'mac:init! "MAC required" mac))
  (let ((state (mac-descriptor:init (mac-descriptor mac) (mac-parameter mac))))
    (mac-state-set! mac state)
    mac))

(define mac:process!
  (case-lambda
   ((mac bv) (mac:process! mac bv 0 (bytevector-length bv)))
   ((mac bv start) (mac:process! mac bv start (bytevector-length bv)))
   ((mac bv start end)
    (unless (mac? mac)
      (springkussen-assertion-violation 'mac:process! "MAC required" mac))
    (let ((state (mac-state mac))
	  (descriptor (mac-descriptor mac)))
      (unless state
	(springkussen-assertion-violation 'mac:process!
					  "MAC is not initialized yet"))
      (mac-descriptor:process! descriptor state bv start end)))))

(define mac:done!
  (case-lambda
   ((mac bv) (mac:done! mac bv 0 (bytevector-length bv)))
   ((mac bv start) (mac:done! mac bv start (- (bytevector-length bv) start)))
   ((mac bv start len)
    (unless (mac? mac)
      (springkussen-assertion-violation 'mac:done! "MAC required" mac))
    (let ((state (mac-state mac))
	  (descriptor (mac-descriptor mac)))
      (unless state
	(springkussen-assertion-violation 'mac:done!
					  "MAC is not initialized yet"))
      (mac-descriptor:done! descriptor state bv start len)))))

(define (mac:mac-size mac)
  (unless (mac? mac)
    (springkussen-assertion-violation 'mac:mac-size "MAC required" mac))
  (let ((descriptor (mac-descriptor mac)))
    (mac-descriptor:mac-size descriptor (mac-parameter mac))))

(define (mac:mac-oid mac)
  (unless (mac? mac)
    (springkussen-assertion-violation 'mac:oid "MAC required" mac))
  (let ((descriptor (mac-descriptor mac)))
    (mac-descriptor:mac-oid descriptor (mac-parameter mac))))
  
)
