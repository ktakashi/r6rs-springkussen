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
	    make-composite-parameter
	    composite-parameter?
	    make-iv-paramater iv-parameter? parameter-iv <iv-parameter>
	    make-counter-parameter counter-parameter?    <counter-parameter>
	    parameter-endian
	    make-rfc3686-parameter rfc3686-parameter?    <rfc3686-parameter>
	    make-round-parameter round-parameter?        <round-parameter>
	    parameter-round
	    )
    (import (rnrs)
	    (springkussen conditions))

    (define-record-type mode-parameter)

    (define-record-type composite-parameter
      (parent mode-parameter)
      (fields parameters)
      (protocol 
       (lambda (p)
	 (lambda params
	   (define (check params)
	     (or (null? params)
		 (and (mode-parameter? (car params))
		      (check (cdr params)))))
	   (unless (check params)
	     (springkussen-assertion-violation
	      'make-composite-parameter "mode-parameter is required" params))
	   ((p) (let loop ((params params) (r '()))
		  (cond ((null? params) (reverse r))
			((composite-parameter? (car params))
			 (loop (cdr params)
			       `(,@(composite-parameter-parameters (car params))
				 . r)))
			(else (loop (cdr params) (cons (car params) r))))))))))

    (define (find-parameter pred composite)
      (cond ((composite-parameter? composite)
	     (let loop ((parameters (composite-parameter-parameters composite)))
	       (cond ((null? parameters) #f)
		     ((pred (car parameters)) (car parameters))
		     (else (loop (cdr parameters))))))
	    ((pred composite) composite)
	    (else #f)))

    ;; mode parameter is immutable so not setter
    (define-syntax define-mode-parameter
      (syntax-rules ()
	;; field
	((_ "field" name ctr pred %ctr %pred (field ...) ((fname acc) rest ...))
	 (define-mode-parameter "field" name ctr pred %ctr %pred
	   (field ... (fname real-accessor acc)) (rest ...)))
	((_ "field" name ctr pred %ctr %pred (field ...) ())
	 (define-mode-parameter "ctr" name ctr pred %ctr %pred (field ...)))
	;; ctr
	((_ "ctr" name (ctr proc) pred %ctr %pred (field ...))
	 (define-mode-parameter "parent" name ctr pred %ctr %pred
	   (protocol proc) (field ...)))
	((_ "ctr" name ctr pred %ctr %pred (field ...))
	 (define-mode-parameter "parent" name ctr pred %ctr %pred 
	   (protocol #f) (field ...)))
	;; parent
	((_ "parent" (name p) ctr pred %ctr %pred protocol fields)
	 (define-mode-parameter "make" name ctr pred %ctr %pred
	   (parent p) protocol fields))
	((_ "parent" name ctr pred %ctr %pred protocol fields)
	 (define-mode-parameter "make" name ctr pred %ctr %pred
	   (parent mode-parameter) protocol fields))
	((_ "make" name ctr pred %ctr %pred parent protocol 
	    ((field real acc) ...))
	 (begin
	   (define-record-type (name ctr %pred)
	     parent
	     protocol
	     (fields (immutable field real) ...))
	   (define (pred o)
	     (or (%pred o)
		 (and (composite-parameter? o)
		      (find-parameter %pred o))))
	   (define (acc o . optional) 
	     (let ((p (find-parameter %pred o)))
	       (cond (p (real p))
		     ((not (null? optional)) (car optional))
		     (else 
		      (springkussen-error (string-append (symbol->string 'acc))
					  "doesn't have the field")))))
	   ...))
	;; entry point
	((_ name ctr pred fields ...)
	 (define-mode-parameter "field" name ctr pred %ctr %pred ()
	   (fields ...)))))

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

