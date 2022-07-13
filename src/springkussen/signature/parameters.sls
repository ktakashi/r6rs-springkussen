;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/signature/parameters.sls - Signer/verifier parameters
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
(library (springkussen signature parameters)
    (export define-signer-parameter
	    define-verifier-parameter
	    
	    signer-parameter? <signer-parameter>
	    make-signer-parameter
	    verifier-parameter? <verifier-parameter>
	    make-verifier-parameter

	    make-signer-digest-parameter signer-digest-parameter?
	    signer-parameter-md
	    make-verifier-digest-parameter verifier-digest-parameter?
	    verifier-parameter-md
	    )
    (import (rnrs)
	    ;; Should not be needed...
	    (springkussen signature descriptor))
(define-syntax define-signer-parameter (make-define-signer-parameter))
(define-syntax define-verifier-parameter (make-define-verifier-parameter))

(define-signer-parameter <signer-digest-parameter>
  make-signer-digest-parameter signer-digest-parameter?
  (digest signer-parameter-md))

(define-signer-parameter <verifier-digest-parameter>
  make-verifier-digest-parameter verifier-digest-parameter?
  (digest verifier-parameter-md))
)
