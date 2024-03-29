;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/key.sls - Key 
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
(library (springkussen cipher key)
    (export (rename (key <key>))
	    key?

	    (rename (key-factory <key-factory>))
	    key-factory? key-factory:generate-key make-key-factory
	    
	    key-parameter? make-key-parameter
	    (rename (key-parameter <key-parameter>))
	    ;; define-key-parameter
	    make-define-key-parameter)
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen misc record))

;; just an interface
(define-record-type key)

;; Probably only for asymmetric keys, but might also be for
;; symmetric in the future, so put it here
(define-record-type key-factory (fields key-generator))
(define (key-factory:generate-key key-factory parameter)
  ((key-factory-key-generator key-factory) parameter))

(define-compositable-record-type key-parameter)

;; TODO we will make it like this after Sagittarius 0.9.9 is released
;; See: https://bitbucket.org/ktakashi/sagittarius-scheme/issues/285/
;; (define-syntax define-key-parameter (make-define-key-parameter))
)

