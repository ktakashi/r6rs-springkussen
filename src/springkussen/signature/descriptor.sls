;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/signature/descriptor.sls - Signer/Verifier descriptor
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
(library (springkussen signature descriptor)
    (export signer-descriptor? signer-descriptor-builder
	    signer-descriptor-name
	    signer-descriptor:init
	    signer-descriptor:process!
	    signer-descriptor:sign

	    verifier-descriptor-name
	    verifier-descriptor:init
	    verifier-descriptor:process!
	    verifier-descriptor:verify
	    
	    verifier-descriptor? verifier-descriptor-builder
	    verifier-descriptor-name

	    signer-parameter? make-signer-parameter
	    verifier-parameter? make-verifier-parameter

	    (rename (signer-parameter <signer-parameter>)
		    (verifier-parameter <verifier-parameter>))
	    make-define-signer-parameter
	    make-define-verifier-parameter
	    )
    (import (rnrs)
	    (springkussen misc record))

(define-record-type signer-descriptor
  (fields name
	  initializer
	  processor
	  finalizer))
(define-syntax signer-descriptor-builder
  (make-record-builder signer-descriptor))

(define-record-type verifier-descriptor
  (fields name
	  initializer
	  processor
	  finalizer))
(define-syntax verifier-descriptor-builder
  (make-record-builder verifier-descriptor))

(define signer-descriptor:init
  (case-lambda
   ((descriptor key) (signer-descriptor:init descriptor key #f))
   ((descriptor key param)
    ((signer-descriptor-initializer descriptor) key param))))

(define signer-descriptor:process!
  (case-lambda
   ((descriptor key bv) (signer-descriptor:process! descriptor key bv 0))
   ((descriptor key bv s)
    (signer-descriptor:process! descriptor key bv s (bytevector-length bv)))
   ((descriptor key bv s e)
    ((signer-descriptor-processor descriptor) key bv s e))))

(define (signer-descriptor:sign descriptor key)
  ((signer-descriptor-finalizer descriptor) key))

(define verifier-descriptor:init
  (case-lambda
   ((descriptor key) (verifier-descriptor:init descriptor key #f))
   ((descriptor key param)
    ((verifier-descriptor-initializer descriptor) key param))))

(define verifier-descriptor:process!
  (case-lambda
   ((descriptor key bv) (verifier-descriptor:process! descriptor key bv 0))
   ((descriptor key bv s)
    (verifier-descriptor:process! descriptor key bv s (bytevector-length bv)))
   ((descriptor key bv s e)
    ((verifier-descriptor-processor descriptor) key bv s e))))

(define (verifier-descriptor:verify descriptor key S)
  ((verifier-descriptor-finalizer descriptor) key S))

(define-compositable-record-type signer-parameter)
(define-compositable-record-type verifier-parameter)

)
