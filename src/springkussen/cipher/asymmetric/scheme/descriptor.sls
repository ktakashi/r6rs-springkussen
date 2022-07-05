;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/asymmetric/scheme/descriptor.sls
;;;      - Asymmetric scheme descriptor
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
(library (springkussen cipher asymmetric scheme descriptor)
    (export asymmetric-scheme-descriptor? asymmetric-scheme-descriptor-builder
	    asymmetric-scheme-descriptor-name

	    asymmetric-scheme-descriptor:get-block-size
	    asymmetric-scheme-descriptor:start
	    asymmetric-scheme-descriptor:encrypt
	    asymmetric-scheme-descriptor:decrypt
	    asymmetric-scheme-descriptor:done
	    
	    asymmetric-state?
	    (rename (asymmetric-state <asymmetric-state>))
	    asymmetric-state-for-encryption?
	    asymmetric-state-for-private-key?

	    )
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen misc record))

(define-record-type asymmetric-scheme-descriptor
  (fields name
	  block-sizer
	  setupper
	  encryptor
	  decryptor
	  finalizer))

(define-syntax asymmetric-scheme-descriptor-builder
  (make-record-builder asymmetric-scheme-descriptor))

(define (asymmetric-scheme-descriptor:start descriptor key param)
  ((asymmetric-scheme-descriptor-setupper descriptor) key param))

(define (asymmetric-scheme-descriptor:encrypt descriptor key bv)
  ((asymmetric-scheme-descriptor-encryptor descriptor) key bv 0))

(define (asymmetric-scheme-descriptor:decrypt descriptor key bv)
  ((asymmetric-scheme-descriptor-decryptor descriptor) key bv 0))

(define (asymmetric-scheme-descriptor:done descriptor key)
  ((asymmetric-scheme-descriptor-finalizer descriptor) key))

(define (asymmetric-scheme-descriptor:get-block-size descriptor state)
  ((asymmetric-scheme-descriptor-block-sizer descriptor) state))

(define-record-type asymmetric-state
  (fields for-encryption?
	  for-private-key?))
)
