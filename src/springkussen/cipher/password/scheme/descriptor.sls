;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/password/scheme/descriptor.sls - PBE Scheme descriptor
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
(library (springkussen cipher password scheme descriptor)
    (export pbe-scheme-descriptor-builder
	    pbe-scheme-descriptor?
	    pbe-scheme-descriptor-name

	    pbe-scheme-descriptor:setup
	    pbe-scheme-descriptor:done
	    pbe-scheme-descriptor:encrypt
	    pbe-scheme-descriptor:decrypt

	    make-pbe-cipher-encryption-parameter
	    pbe-cipher-encryption-scheme-parameter?
	    pbe-cipher-parameter-encryption-scheme

	    make-pbe-cipher-kdf-parameter pbe-cipher-kdf-parameter?
	    pbe-cipher-parameter-kdf

	    make-pbe-cipher-salt-parameter pbe-cipher-salt-parameter?
	    pbe-cipher-parameter-salt

	    make-pbe-cipher-iteration-parameter pbe-cipher-iteration-parameter?
	    pbe-cipher-parameter-iteration
	    )
    (import (rnrs)
	    (springkussen cipher parameter)
	    (springkussen conditions)
	    (springkussen misc record))

(define-syntax define-pbe-parameter (make-define-cipher-parameter))

(define-pbe-parameter pbe-cipher-encryption-scheme-parameter
  make-pbe-cipher-encryption-parameter pbe-cipher-encryption-scheme-parameter?
  (scheme pbe-cipher-parameter-encryption-scheme))

(define-pbe-parameter pbe-cipher-kdf-parameter
  make-pbe-cipher-kdf-parameter pbe-cipher-kdf-parameter?
  (kdf pbe-cipher-parameter-kdf))

(define-pbe-parameter pbe-cipher-salt-parameter
  make-pbe-cipher-salt-parameter pbe-cipher-salt-parameter?
  (salt pbe-cipher-parameter-salt))

(define-pbe-parameter pbe-cipher-iteration-parameter
  make-pbe-cipher-iteration-parameter pbe-cipher-iteration-parameter?
  (iteration pbe-cipher-parameter-iteration))

(define-record-type pbe-scheme-descriptor
  (fields name
	  setupper
	  padder
	  encryptor
	  decryptor
	  finalizer))

(define-syntax pbe-scheme-descriptor-builder
  (make-record-builder pbe-scheme-descriptor))

(define (pbe-scheme-descriptor:setup desc password param)
  ((pbe-scheme-descriptor-setupper desc) password param))

(define (pbe-scheme-descriptor:done desc state)
  ((pbe-scheme-descriptor-finalizer desc) state))

(define (pbe-scheme-descriptor:padding desc state M)
  ((pbe-scheme-descriptor-padder desc) state M #t))

(define (pbe-scheme-descriptor:unpadding desc state M)
  ((pbe-scheme-descriptor-padder desc) state M #f))

(define (pbe-scheme-descriptor:encrypt desc key pt ps ct cs)
  ((pbe-scheme-descriptor-encryptor desk) key pt ps ct cs))

(define (pbe-scheme-descriptor:decrypt desc key ct cs pt ps)
  ((pbe-scheme-descriptor-decryptor desk) key ct cs pt ps))

)

