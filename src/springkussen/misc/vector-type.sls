;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/misc/vector-type.sls - Vector type
;;;
;;;  Copyright (c) 2022 Takashi Kato. All rights reserved.
;;;
;;;  Redistribution and use in source and binary forms, with or without
;;;  modification, are permitted provided that the following conditions
;;;  are met:
;;;
;;;  1. Redistributions of source code must retain the above copyright
;;;     notice, this list of conditions and the following disclaimer.
;;;
;;;  2. Redistributions in binary form must reproduce the above copyright
;;;     notice, this list of conditions and the following disclaimer in the
;;;     documentation and/or other materials provided with the distribution.
;;;
;;;  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;;;  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;;;  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;;;  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;;;  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;;;  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
;;;  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;;;  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;;;  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;;  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;;  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

;; completely copied from Sagittarius' (core misc)
#!r6rs
(library (springkussen misc vector-type)
    (export define-vector-type)
    (import (rnrs))

(define-syntax define-vector-type
  (lambda (x)
    (define (order-args args fs)
      (unless (= (length args) (length fs))
	(syntax-violation 'define-vector-type
	  "Constructor argument count doesn't match with field count"
	  (syntax->datum args) (syntax->datum fs)))
      (map (lambda (a) 
	     (cond ((memp (lambda (f) (bound-identifier=? a f)) fs) => car)
		   (else
		    (syntax-violation 'define-vector-type "unknown tag" a))))
	   args))
    (define (generate-accessor k acc)
      ;; starting from 1 because 0 is type tag
      (let loop ((r '()) (i 1) (acc acc))
	(syntax-case acc ()
	  (((get set) rest ...)
	   (with-syntax ((n (datum->syntax k i)))
	     (loop (cons #'(begin (define (get o) (vector-ref o n))
				  (define (set o v) (vector-set! o n v)))
			 r)
		   (+ i 1)
		   #'(rest ...))))
	  (((name) rest ...)
	   (with-syntax ((n (datum->syntax k i)))
	     (loop (cons #'(define (name o) (vector-ref o n)) r)
		   (+ i 1)
		   #'(rest ...))))
	  (() r))))
    (syntax-case x ()
      ((k type (ctr args ...) pred
	  (field accessor ...) ...)
       (and (identifier? #'pred) (identifier? #'type) (identifier? #'ctr))
       (with-syntax (((ordered-args ...)
		      (order-args #'(args ...) #'(field ...)))
		     ((acc ...)
		      (generate-accessor #'k #'((accessor ...) ...))))
	 #'(begin
	     (define (ctr args ...) (vector 'type ordered-args ...))
	     (define (pred o) 
	       (and (vector? o)
		    (= (vector-length o) (+ (length '(field ...)) 1))
		    (eq? (vector-ref o 0) 'type)))
	     acc ...))))))
)
