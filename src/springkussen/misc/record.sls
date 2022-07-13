;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/misc/record.sls - Misc record operations
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
;; The implementation is from aeolus, which is written by me :)
(library (springkussen misc record)
    (export make-record-builder from
	    define-compositable-record-type)
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen misc lists))

(define-syntax define-compositable-record-type
  (lambda (x)
    (define (make-record-ctr&pred k name)
      (define n (symbol->string (syntax->datum name)))
      (datum->syntax k
       (list (string->symbol (string-append "make-" n))
	     (string->symbol (string-append n "?")))))
    (define (make-composite-name&definer k name)
      (define n (symbol->string (syntax->datum name)))
      (datum->syntax k
       (list (string->symbol (string-append "composite-" n))
	     (string->symbol (string-append "make-define-" n )))))
    (syntax-case x ()
      ((k name clause ...)
       (identifier? #'name)
       (with-syntax (((ctr pred) (make-record-ctr&pred #'k #'name)))
	 #'(k (name ctr pred) clause ...)))
      ((k (name ctr pred) clause ...)
       (with-syntax (((composite-name definer-name)
		      (make-composite-name&definer #'k #'name)))
       #'(begin
	   (define-record-type (name dummy0 pred) clause ...)
	   (define-record-type (composite-name dummy1 cpred)
	     (parent name)
	     (fields (immutable elements get-elements))
	     (protocol
	      (lambda (p)
		(lambda params
		  (unless (for-all pred params)
		    (springkussen-assertion-violation 'composite-name
		     (string-append (symbol->string 'name) " is required")
		     params))
		  ((p) (apply append (map (lambda (p)
					    (if (cpred p)
						(get-elements p)
						(list p))) params)))))))
	   (define ctr dummy1)
	   (define (find-parameter pred composite)
	     (cond ((cpred composite)
		    (let loop ((param (get-elements composite)))
		      (cond ((null? param) #f)
			    ((pred (car param)) (car param))
			    (else (loop (cdr param))))))
		   ((pred composite) composite)
		   (else #f)))

	   (define-syntax definer-name
	     (lambda (xx)
	       (syntax-case xx ()
		 ((k) #'(k name))
		 ((_ <parent>)
		  #'(lambda (xxx)
		      (syntax-case xxx ()
			;; field
			((k "field" name ctr pred %ctr %pred
			    (field ((... ...) (... ...)))
			    ((fname acc) rest ((... ...) (... ...))))
			 #'(k "field" name ctr pred %ctr %pred
			      (field ((... ...) (... ...))
				     (fname real-accessor acc))
			      (rest ((... ...) (... ...)))))
			((k "field" name ctr pred %ctr %pred
			    (field ((... ...) (... ...))) ())
			 #'(k "ctr" name ctr pred %ctr %pred
			      (field ((... ...) (... ...)))))
			;; ctr
			((k "ctr" name (ctr proc) pred %ctr %pred
			    (field ((... ...) (... ...))))
			 #'(k "parent" name ctr pred %ctr %pred (protocol proc)
			      (field ((... ...) (... ...)))))
			((k "ctr" name ctr pred %ctr %pred
			    (field ((... ...) (... ...))))
			 #'(k "parent" name ctr pred %ctr %pred  (protocol #f)
			      (field ((... ...) (... ...)))))
			;; parent
			((k "parent" (name p) ctr pred %ctr %pred
			    protocol fields)
			 #'(k "make" name ctr pred %ctr %pred
			      (parent p) protocol fields))
			((k "parent" name ctr pred %ctr %pred protocol fields)
			 #'(k "make" name ctr pred %ctr %pred
			      (parent <parent>) protocol fields))
			((k "make" name ctr pred %ctr %pred parent protocol
			    ((field real acc) ((... ...) (... ...))))
			 #'(begin
			     (define-record-type (name ctr %pred)
			       parent
			       protocol
			       (fields (immutable field real)
				       ((... ...) (... ...))))
			     (define (pred o)
			       (or (%pred o)
				   (and (cpred o)
					(find-parameter %pred o))))
			     (define (acc o . optional)
			       (let ((p (find-parameter %pred o)))
				 (cond (p (real p))
				       ((not (null? optional)) (car optional))
				       (else 
					(springkussen-error 'acc
					 "doesn't have the field")))))
			     ((... ...) (... ...))))
			;; entry point
			((k name ctr pred fields ((... ...) (... ...)))
			 #'(k "field" name ctr pred %ctr %pred ()
			      (fields ((... ...) (... ...)))))))))))))))))


(define-syntax from (syntax-rules ()))
(define-syntax make-record-builder
  (lambda (xx)
    (define (->name rt)
      (string->symbol
       (string-append
	(symbol->string (syntax->datum rt)) "-builder")))
    (define (collect-defaults k fields)
      (let loop ((acc '()) (fields fields))
	(syntax-case fields ()
	  (((field default-value) rest ...)
	   (loop (cons (list #'field #'default-value #f) acc) #'(rest ...)))
	  (((field default-value conv) rest ...)
	   (loop (cons (list #'field #'default-value #'conv) acc) #'(rest ...)))
	  (() acc))))
    (syntax-case xx ()
      ((k ?record-type)
       #'(k ?record-type ()))
      ((kk ?record-type ((?fields ...) ...))
       (with-syntax ((?name (datum->syntax #'kk (->name #'?record-type)))
		     (((?field ?default-value ?converter) ...)
		      (collect-defaults #'kk #'((?fields ...) ...)))
		     ((rtd) (generate-temporaries '("rtd"))))
	 #'(lambda (x)
	     (syntax-case x (from)
	       ((k (from record) (name value) (... ...))
		#'(apply (record-constructor
			  (record-constructor-descriptor ?record-type))
			 (sort-values (record-type-descriptor ?record-type)
			  (list (cons* '?field ?default-value ?converter) ...)
			  (merge-values
			   (record-type-descriptor ?record-type)
			   record
			   (list (cons 'name value) (... ...))))))
	       ((k (name value) (... ...))
		#'(apply (record-constructor
			  (record-constructor-descriptor ?record-type))
			 (sort-values
			  (record-type-descriptor ?record-type)
			  (list (cons* '?field ?default-value ?converter) ...)
			  (list (cons 'name value) (... ...))))))))))))

(define (merge-values rtd record provided-values)
  (define (child-of? rtd record)
    (let loop ((child (record-rtd record)))
      (cond ((not child) #f)
	    ((eq? child rtd))
	    (else (loop (record-type-parent child))))))
  ;; TODO replace with record-type-all-field-name&accessors
  (define (collect-fields&value rtd record)
    (let loop ((rtd rtd) (r '()))
      (if rtd
	  (do ((i 0 (+ i 1))
	       (fields (record-type-field-names rtd))
	       (r r (cons (cons (vector-ref fields i)
				((record-accessor rtd i) record))
			  r)))
	      ((eq? i (vector-length fields))
	       (loop (record-type-parent rtd) r)))
	  r)))
  ;; is this actually valid in R6RS?
  (unless (child-of? rtd record)
    (assertion-violation 'record-builder "Wrong record type" record))
  (let ((record-values (collect-fields&value rtd record)))
    (lset-union (lambda (a b) (eq? (car a) (car b)))
		provided-values record-values)))

(define (sort-values rtd default-values provided-values)
  (define fields (record-type-all-field-names rtd))
  (define (emit fields values)
    (define (find-value field values)
      (cond ((assq field values) =>
	     (lambda (slot)
	       (let ((v (cdr slot)))
		 (cond ((assq field default-values) =>
			(lambda (d)
			  (let ((conv (cddr d)))
			    (if conv (conv v) v))))
		       (else v)))))
	    ((assq field default-values) =>
	     (lambda (fvd)
	       (let ((v (cadr fvd))
		     (conv (cddr fvd)))
		 (if conv (conv v) v))))
	    (else #f)))
    (do ((fields fields (cdr fields))
	 (acc '() (cons (find-value (car fields) values) acc)))
	((null? fields) (reverse acc))))
  (let ((non-exists (lset-difference eq? (map car provided-values) fields)))
    (unless (null? non-exists)
      (assertion-violation 'record-builder
			   "Unknown fields" non-exists)))
  (emit fields provided-values))

(define (record-type-all-field-name&accessors rtd) 
  (let loop ((rtd rtd) (names '()) (accessors '()))
    (if rtd
	(do ((i 0 (+ i 1))
	     (fields (record-type-field-names rtd))
	     (acc '() (cons (record-accessor rtd i) acc)))
	    ((eq? i (vector-length fields))
	     (loop (record-type-parent rtd)
		   (cons (vector->list fields) names)
		   (cons (reverse acc) accessors))))
	(values (apply append names) (apply append accessors)))))

(define (record-type-all-field-names rtd)
  (let-values (((names _) (record-type-all-field-name&accessors rtd)))
    names))
(define (record-type-all-field-accessors rtd)
  (let-values (((_ acc) (record-type-all-field-name&accessors rtd)))
    acc))

)

