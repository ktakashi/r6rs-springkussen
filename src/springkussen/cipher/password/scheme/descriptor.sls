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
    (export (rename (symmetric-mode-descriptor-builder
		     pbe-scheme-descriptor-builder)
		    (symmetric-mode-descriptor? pbe-scheme-descriptor?)
		    (symmetric-mode-descriptor-name pbe-scheme-descriptor-name))
	    
	    make-pbe-cipher-encryption-scheme-parameter
	    pbe-cipher-encryption-scheme-parameter?
	    pbe-cipher-parameter-encryption-scheme

	    make-pbe-cipher-kdf-parameter pbe-cipher-kdf-parameter?
	    pbe-cipher-parameter-kdf

	    make-pbe-cipher-key-size-parameter pbe-cipher-key-size-parameter?
	    pbe-cipher-parameter-key-size
	    
	    make-pbe-cipher-salt-parameter pbe-cipher-salt-parameter?
	    pbe-cipher-parameter-salt

	    make-pbe-cipher-iteration-parameter pbe-cipher-iteration-parameter?
	    pbe-cipher-parameter-iteration)
    (import (rnrs)
	    (springkussen cipher parameter)
	    (springkussen cipher symmetric mode descriptor)
	    (springkussen conditions)
	    (springkussen misc record))

(define-syntax define-pbe-parameter (make-define-cipher-parameter))

(define-pbe-parameter pbe-cipher-encryption-scheme-parameter
  make-pbe-cipher-encryption-scheme-parameter
  pbe-cipher-encryption-scheme-parameter?
  (scheme pbe-cipher-parameter-encryption-scheme))

(define-pbe-parameter pbe-cipher-kdf-parameter
  make-pbe-cipher-kdf-parameter pbe-cipher-kdf-parameter?
  (kdf pbe-cipher-parameter-kdf))

(define-pbe-parameter pbe-cipher-key-size-parameter
  make-pbe-cipher-key-size-parameter pbe-cipher-key-size-parameter?
  (key-size pbe-cipher-parameter-key-size))

(define-pbe-parameter pbe-cipher-salt-parameter
  make-pbe-cipher-salt-parameter pbe-cipher-salt-parameter?
  (salt pbe-cipher-parameter-salt))

(define-pbe-parameter pbe-cipher-iteration-parameter
  make-pbe-cipher-iteration-parameter pbe-cipher-iteration-parameter?
  (iteration pbe-cipher-parameter-iteration))
)

