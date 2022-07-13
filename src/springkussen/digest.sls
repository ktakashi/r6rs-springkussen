;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/digest.sls - Digest APIs
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
(library (springkussen digest)
    (export digester? make-digester
	    digester:digest  ;; High level
	    digester:digest! ;; High level
	    digester:init!
	    digester:process!
	    digester:done!
	    digester:done
	    
	    digest-descriptor?
	    digest-descriptor-name
	    digest-descriptor-digest-size
	    digest-descriptor-block-size
	    digest-descriptor-oid
	    (rename (md5-descriptor        *digest:md5*)
		    (sha1-descriptor       *digest:sha1*)
		    (sha224-descriptor     *digest:sha224*)
		    (sha256-descriptor     *digest:sha256*)
		    (sha384-descriptor     *digest:sha384*)
		    (sha512-descriptor     *digest:sha512*)
		    (sha512/224-descriptor *digest:sha512/224*)
		    (sha512/256-descriptor *digest:sha512/256*)))
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen digest descriptor)
	    (springkussen digest md5)
	    (springkussen digest sha1)
	    (springkussen digest sha256)
	    (springkussen digest sha512))

(define-record-type digester
  (fields (mutable state)
	  descriptor)
  (protocol (lambda (p)
	      (lambda (descriptor)
		(unless (digest-descriptor? descriptor)
		  (springkussen-assertion-violation
		   'make-digester "Digest descriptor required" descriptor))
		(p #f descriptor)))))

(define (digester:digest digester bv)
  (let ((size (digest-descriptor-digest-size (digester-descriptor digester))))
    (digester:digest! digester bv (make-bytevector size) 0)))

(define digester:digest!
  (case-lambda
   ((digester bv out) (digester:digest! digester bv out 0))
   ((digester bv out pos)
    (digester:init! digester)
    (digester:process! digester bv)
    (digester:done! digester out pos)
    out)))

(define (digester:init! digester)
  (unless (digester? digester)
    (springkussen-assertion-violation 'digester:init!
				      "Digester required" digester))
  (digester-state-set! digester
   (digest-descriptor:init (digester-descriptor digester)))
  digester)

(define digester:process!
  (case-lambda
   ((digester bv) (digester:process! digester bv 0 (bytevector-length bv)))
   ((digester bv start)
    (digester:process! digester bv start (bytevector-length bv)))
   ((digester bv start end)
    (unless (digester? digester)
      (springkussen-assertion-violation 'digester:process!
					"Digester required" digester))
    (let ((state (digester-state digester)))
      (unless (digest-state? state)
	(springkussen-assertion-violation 'digester:process!
					  "Digester is not initialized yet"
					  state))
      (digest-descriptor:process! (digester-descriptor digester)
				  state bv start end)
      digester))))

(define (digester:done digester)
  (let ((size (digest-descriptor-digest-size (digester-descriptor digester))))
    (digester:done! digester (make-bytevector size 0))))

(define digester:done!
  (case-lambda
   ((digester out) (digester:done! digester out 0))
   ((digester out pos)
    (unless (digester? digester)
      (springkussen-assertion-violation 'digester:done!
					"Digester required" digester))
    (let ((state (digester-state digester)))
      (unless (digest-state? state)
	(springkussen-assertion-violation 'digester:done!
					  "Digester is not initialized yet"))
      (let ((r (digest-descriptor:done! (digester-descriptor digester)
					state out pos)))
	(digester-state-set! digester #f)
	r)))))

)
