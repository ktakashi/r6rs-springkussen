;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/symmetric/scheme/descriptor.sls - Scheme descriptor
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
(library (springkussen cipher symmetric scheme descriptor)
    (export symmetric-scheme-descriptor-builder
	    symmetric-scheme-descriptor?
	    symmetric-scheme-descriptor-key-length*
	    symmetric-scheme-descriptor-block-size
	    symmetric-scheme-descriptor-default-round
	    symmetric-scheme-descriptor-encryptor
	    symmetric-scheme-descriptor-decryptor

	    symmetric-scheme-descriptor:setup
	    symmetric-scheme-descriptor:done
	    )
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen misc record))

(define-record-type symmetric-scheme-descriptor
  (fields key-length*
	  block-size
	  default-round
	  setupper
	  encryptor
	  decryptor
	  finalizer))

(define-syntax symmetric-scheme-descriptor-builder
  (make-record-builder symmetric-scheme-descriptor))

(define (symmetric-scheme-descriptor:setup desc key param)
  (define allowed-key-length* (symmetric-scheme-descriptor-key-length* desc))
  (if (list? allowed-key-length*)
      ;; fixed list
      (unless (memq (bytevector-length key) allowed-key-length*)
	(springkussen-assertion-violation 'symmetric-scheme-descriptor:setup
	 "Invalid key length" (bytevector-length key)))
      ;; range
      (let ((min (car allowed-key-length*)) (max (cdr allowed-key-length*)))
	(unless (<= min (bytevector-length key) max)
	  (springkussen-assertion-violation 'symmetric-scheme-descriptor:setup
	   "Invalid key length" (bytevector-length key)))))
  ((symmetric-scheme-descriptor-setupper desc) key param))

(define (symmetric-scheme-descriptor:done desc key)
  ((symmetric-scheme-descriptor-finalizer desc) key))
)

