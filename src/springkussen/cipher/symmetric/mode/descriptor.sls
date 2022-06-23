;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/symmetric/mode/descriptor.sls - Mode descriptor
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
(library (springkussen cipher symmetric mode descriptor)
    (export symmetric-mode-descriptor-builder
	    symmetric-mode-descriptor?
	    symmetric-mode-descriptor-starter
	    symmetric-mode-descriptor-encryptor
	    symmetric-mode-descriptor-decryptor
	    symmetric-mode-descriptor-aad-updator
	    symmetric-mode-descriptor-finalizer

	    symmetric-mode-descriptor:start
	    symmetric-mode-descriptor:encrypt
	    symmetric-mode-descriptor:decrypt
	    symmetric-mode-descriptor:done

	    symmetric-mode-descriptor:set-iv!
	    symmetric-mode-descriptor:get-iv
	    )
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen misc record))

(define-record-type symmetric-mode-descriptor
  (fields starter
	  encryptor
	  decryptor
	  iv-setter
	  iv-getter
	  aad-updator
	  finalizer))

(define-syntax symmetric-mode-descriptor-builder
  (make-record-builder symmetric-mode-descriptor))

(define (symmetric-mode-descriptor:start desc scheme key param)
  ((symmetric-mode-descriptor-starter desc) scheme key param))

(define (symmetric-mode-descriptor:encrypt desc mode-specific pt)
  ((symmetric-mode-descriptor-encryptor desc) mode-specific pt))

(define (symmetric-mode-descriptor:decrypt desc mode-specific ct)
  ((symmetric-mode-descriptor-decryptor desc) mode-specific ct))

(define (symmetric-mode-descriptor:done desc mode-specific)
  ((symmetric-mode-descriptor-finalizer desc) mode-specific))

(define (symmetric-mode-descriptor:set-iv! desc mode-specific iv)
  (let ((setter (symmetric-mode-descriptor-iv-setter desc)))
    (unless (procedure? setter)
      (springkussen-assertion-violation 'set-iv "Not supported operation"))
    (setter mode-specific iv)))

(define (symmetric-mode-descriptor:get-iv desc mode-specific)
  (let ((getter (symmetric-mode-descriptor-iv-getter desc)))
    (unless (procedure? getter)
      (springkussen-assertion-violation 'get-iv "Not supported operation"))
    (getter mode-specific)))
)

