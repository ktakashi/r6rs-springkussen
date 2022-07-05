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
	    
	    key-parameter?
	    (rename (key-parameter <key-parameter>)
		    (make-composite-key-parameter make-key-parameter))
	    define-key-parameter)
    (import (rnrs)
	    (springkussen conditions))

;; just an interface
(define-record-type key)

;; Probably only for asymmetric keys, but might also be for
;; symmetric in the future, so put it here
(define-record-type key-factory (fields key-generator))
(define (key-factory:generate-key key-factory parameter)
  ((key-factory-key-generator key-factory) parameter))

(define-record-type key-parameter)
(define-record-type composite-key-parameter
  (parent key-parameter)
  (fields parameters)
  (protocol
   (lambda (p)
     (lambda params
       (unless (for-all key-parameter? params)
	 (springkussen-assertion-violation 'make-composite-key-parameter
	  "key-parameters are required" params))
       ;; simple append-map :D
       ((p) (apply append (map (lambda (p)
				 (if (composite-key-parameter p)
				     (composite-key-parameter-parameters p)
				     (list p))) params)))))))

(define (find-parameter pred composite)
  (cond ((composite-key-parameter? composite)
	 (let loop ((parameters (composite-key-parameter-parameters composite)))
	   (cond ((null? parameters) #f)
		 ((pred (car parameters)) (car parameters))
		 (else (loop (cdr parameters))))))
	((pred composite) composite)
	(else #f)))

(define-syntax define-key-parameter
  (syntax-rules ()
    ;; field
    ((_ "field" name ctr pred %ctr %pred (field ...) ((fname acc) rest ...))
     (define-key-parameter "field" name ctr pred %ctr %pred
       (field ... (fname real-accessor acc)) (rest ...)))
    ((_ "field" name ctr pred %ctr %pred (field ...) ())
     (define-key-parameter "ctr" name ctr pred %ctr %pred (field ...)))
    ;; ctr
    ((_ "ctr" name (ctr proc) pred %ctr %pred (field ...))
     (define-key-parameter "parent" name ctr pred %ctr %pred
       (protocol proc) (field ...)))
    ((_ "ctr" name ctr pred %ctr %pred (field ...))
     (define-key-parameter "parent" name ctr pred %ctr %pred 
       (protocol #f) (field ...)))
    ;; parent
    ((_ "parent" (name p) ctr pred %ctr %pred protocol fields)
     (define-key-parameter "make" name ctr pred %ctr %pred
       (parent p) protocol fields))
    ((_ "parent" name ctr pred %ctr %pred protocol fields)
     (define-key-parameter "make" name ctr pred %ctr %pred
       (parent key-parameter) protocol fields))
    ((_ "make" name ctr pred %ctr %pred parent protocol 
	((field real acc) ...))
     (begin
       (define-record-type (name ctr %pred)
	 parent
	 protocol
	 (fields (immutable field real) ...))
       (define (pred o)
	 (or (%pred o)
	     (and (composite-key-parameter? o)
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
     (define-key-parameter "field" name ctr pred %ctr %pred ()
       (fields ...)))))

)

