;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/symmetric/mode/parameter.sls - Mode parameter
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
(library (springkussen cipher symmetric mode parameter)
    (export mode-parameter?
	    (rename (make-cipher-parameter make-composite-parameter))
	    
	    make-iv-paramater iv-parameter? parameter-iv <iv-parameter>
	    make-counter-parameter counter-parameter?    <counter-parameter>
	    parameter-endian
	    make-rfc3686-parameter rfc3686-parameter?    <rfc3686-parameter>
	    make-round-parameter round-parameter?        <round-parameter>
	    parameter-round
	    )
    (import (rnrs)
	    (springkussen cipher parameter)
	    (springkussen conditions))

(define-record-type mode-parameter (parent <cipher-parameter>))
;; mode parameter is immutable so not setter
(define-syntax define-mode-parameter
  (make-define-cipher-parameter mode-parameter))

(define-mode-parameter <round-parameter> 
  make-round-parameter round-parameter?
  (round parameter-round))

(define-mode-parameter <iv-parameter> 
  (make-iv-paramater 
   (lambda (p)
     (lambda (iv)
       (unless (bytevector? iv)
	 (springkussen-assertion-violation
	  'make-iv-paramater "iv must be a bytevector"))
       ((p) (bytevector-copy iv)))))
  iv-parameter?
  (iv parameter-iv))

(define-mode-parameter (<counter-parameter> <iv-parameter>)
  (make-counter-parameter 
   (lambda (p) 
     (define (check type)
       (unless (memq type '(big little))
	 (springkussen-assertion-violation
	  'make-counter-parameter "big or little is required" type)))
     (case-lambda
      ((iv) ((p iv) 'big))
      ((iv type) (check type) ((p iv) type)))))
  counter-parameter?
  (endian parameter-endian))

(define-mode-parameter (<rfc3686-parameter> <counter-parameter>)
  (make-rfc3686-parameter
   (lambda (p)
     (define (make-iv iv nonce type)
       (let ((v (make-bytevector 16 0)) ;; AES blocksize
	     (nlen (bytevector-length nonce))
	     (ivlen (bytevector-length iv)))
	 (if (eq? type 'big)
	     (begin
	       (bytevector-copy! v 0 nonce 0 nlen)
	       (bytevector-copy! v nlen iv 0 ivlen)
	       (bytevector-u8-set! v 15 1))
	     (begin
	       (bytevector-u8-set! v 0 1)
	       (bytevector-copy! v 4 iv 0 4)
	       (bytevector-copy! v (+ 4 ivlen) nonce 0 nlen)))
	 v))
     (case-lambda
      ((iv nonce) 
       (let ((iv (make-iv iv nonce 'big)))
	 ((p iv 'big))))
      ((iv nonce type) 
       (let ((iv (make-iv iv nonce type)))
	 ((p iv type)))))))
  rfc3686-parameter?)

)

