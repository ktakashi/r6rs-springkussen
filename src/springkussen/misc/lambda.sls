;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/misc/lambda.sls - Misc lambda
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
(library (springkussen misc lambda)
    (export define/typed
	    lambda/typed
	    case-lambda/typed
	    list-of?)
    (import (rnrs)
	    (springkussen conditions))

;; a bit weird location
(define (list-of? pred) (lambda (v) (for-all pred v)))

(define-syntax define/typed
  (syntax-rules ()
    ((_ (name args ... . rest) body0 body1 ...)
     (define name (lambda/typed (args ... . rest) body0 body1 ...)))))
    
(define-syntax lambda/typed
  (lambda (x)
    (define (parse-pred pred)
      (syntax-case pred (and or quote)
	((and p0 p1 ...)
	 (with-syntax ((pp0 (parse-pred #'p0))
		       (pp1 (parse-pred #'(and p1 ...))))
	   #'(lambda (v) (and (pp0 v) (pp1 v)))))
	((and) #'(lambda (v) #t))
	((or p0 p1 ...)
	 (with-syntax ((pp0 (parse-pred #'p0))
		       (pp1 (parse-pred #'(or p1 ...))))
	   #'(lambda (v) (or (pp0 v) (pp1 v)))))
	((or) #'(lambda (v) #f))
	;; general, #t = any, #f = (not v)
	(p
	 (boolean? (syntax->datum #'p))
	 (if (syntax->datum #'p)
	     #'(lambda (v) #t)
	     #'(lambda (v) (not v))))
	;; suppose it's procedure
	(p
	 (identifier? #'p)
	 #'p)
	;; evaludate :)
	((p ...) #'(lambda (v) (let ((t (p ...))) (t v))))
	;; compare with equal?
	((quote p) #'(lambda (v) (equal? v p)))))
    (define (make-message v pred)
      (define var (syntax->datum v))
      (define procs (syntax->datum pred))
      (let-values (((out e) (open-string-output-port)))
	(put-datum out var)
	(put-string out " must satisfy the ")
	(put-datum out procs)
	(e)))
    (define (parse-formals vars)
      (syntax-case vars ()
	(() #'())
	(((v pred) rest ...)
	 (with-syntax ((r (parse-pred #'pred))
		       (msg (make-message #'v #'pred))
		       ((t) (generate-temporaries '(v)))
		       ((rest ...) (parse-formals #'(rest ...))))
	   #'((v (t r) msg) rest ...)))
	((v rest ...)
	 (with-syntax (((rest ...) (parse-formals #'(rest ...))))
	   #'((v (t #f) "") rest ...)))
	(v (syntax-violation 'lambda/typed "Invalid formals"
			     (syntax->datum #'v)))))
    (syntax-case x ()
      ((_ (vars ... . rest) body0 body* ...)
       (with-syntax ((((v (p pred) msg) ...) (parse-formals #'(vars ...))))
	 #'(lambda (v ... . rest)
	     (let ((p pred)) ;; let's hope the compiler does lambda lifting...
	       (unless (or (not p) (p v))
		 (springkussen-assertion-violation #f msg v)))
	     ...
	     (let () ;; wrap with let for internal defines
	       body0
	       body* ...))))
      ((_ arg* body0 body* ...)
       (identifier? #'arg*)
       #'(lambda arg* body0 body* ...)))))

;; TODO it's a lazy implementation assuming some lambda lifting
;;      is done by compilers...
(define-syntax case-lambda/typed
  (lambda (x)
    (define (parse-formals vars)
      (syntax-case vars ()
	(() #'())
	(((v pred) rest ...)
	 (with-syntax (((rest ...) (parse-formals #'(rest ...))))
	   #'(v rest ...)))
	((v rest ...)
	 (identifier? #'v)
	 (with-syntax (((rest ...) (parse-formals #'(rest ...))))
	   #'(v rest ...)))
	(v (syntax-violation 'case-lambda/typed
			     "Invalid formals"
			     (syntax->datum #'v)
			     (syntax->datum vars)))))
    (syntax-case x ()
      ((k "parse" (clause* ...) ()) #'(case-lambda clause* ...))
      ((k "parse" (clause* ...) (((vars ...) body* ...) rest ...))
       (with-syntax (((v ...) (parse-formals #'(vars ...))))
	 #'(k "parse"
	      (clause* ...
		       ((v ...) ((lambda/typed (vars ...) body* ...) v ...)))
	      (rest ...))))
      ((k "parse" (clause* ...) (((vars ... . r) body* ...) rest ...))
       (with-syntax (((v ...) (parse-formals #'(vars ...))))
	 #'(k "parse"
	      (clause* ... ((v ... . r)
			    (apply (lambda/typed (vars ... . r) body* ...)
				   v ... r)))
	      (rest ...))))
      ((k (vars body0 body* ...) rest ...)
       #'(k "parse" () ((vars body0 body* ...) rest ...))))))

)

