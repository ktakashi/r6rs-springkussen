;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/pem/reader.sls - PEM reader
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

;; ref: https://www.rfc-editor.org/rfc/rfc7468
#!r6rs
(library (springkussen pem reader)
    (export pem-object? pem-object-label pem-object-content
	    make-pem-object
	    read-pem-object string->pem-object
	    write-pem-object pem-object->string
	    )
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen misc base64)
	    (springkussen misc lambda))
(define-record-type pem-object
  (fields label content))

(define write-pem-object
  (case-lambda/typed
   ((pem-object) (write-pem-object pem-object (current-output-port)))
   (((pem-object pem-object?)
     (out (and output-port? textual-port?)))
    (let ((content (base64-encode (pem-object-content pem-object)))
	  (label (pem-object-label pem-object)))
      (put-string out "-----BEGIN ")
      (put-string out label)
      (put-string out "-----")
      (newline out)
      (unless (zero? (bytevector-length content))
	(put-string out (utf8->string content))
	(newline out))
      (put-string out "-----END ")
      (put-string out label)
      (put-string out "-----")
      (newline out)))))

(define/typed (pem-object->string (pem-object pem-object?))
  (let-values (((out e) (open-string-output-port)))
    (write-pem-object pem-object out)
    (e)))

(define read-pem-object
  (case-lambda/typed
   (() (read-pem-object (current-input-port)))
   (((in (and input-port? textual-port?)))
    (let-values (((label content) (read-pem in)))
      (make-pem-object label content)))))

(define (string->pem-object s) (read-pem-object (open-string-input-port s)))

(define (read-pem in)
  (let loop ((label #f) (content '()))
    (let ((line (get-line in)))
      (cond ((eof-object? line)
	     (springkussen-error 'read-pem-object
				 "Unexpected EOL while reading PEM"))
	    ((string-prefix? "-----BEGIN " line)
	     (when label
	       (springkussen-error 'read-pem-object
				   "Label mustn't appear in PEM content"))
	     (let ((label (check-label line 11)))
	       (loop label content)))
	    ((string-prefix? "-----END " line)
	     (unless label
	       (springkussen-error 'read-pem-object "No BEGIN label"))
	     (let ((end-label (check-label line 9)))
	       (unless (string=? label end-label)
		 (springkussen-error 'read-pem-object
				     "BEGIN and END label didn't match"))
	       (values label (decode-content (reverse content)))))
	    (else
	     (loop label (if label (cons line content) content)))))))

(define (check-label line index)
  (define (err) (springkussen-error 'read-pem-object "Invalid PEM label" line))
  (define len (string-length line))
  
  (let loop ((i index) (label '()))
    (cond ((= i len) (err))
	  ((eqv? (string-ref line i) #\-)
	   (let loop2 ((j (+ i 1)) (c 1))
	     (cond ((= j len)
		    (if (= c 5)
			(list->string (reverse label))
			(err)))
		   ((eqv? (string-ref line j) #\-)
		    (loop2 (+ j 1) (+ c 1)))		   
		   (else
		    (unless (= c 1) (err))
		    ;; A-B case
		    (loop (+ i 1) (cons #\- label))))))
	  (else (loop (+ i 1) (cons (string-ref line i) label))))))

(define (decode-content contents)
  (define base64 (apply string-append contents))
  (base64-decode (string->utf8 base64)))

;; Simple string-prefix? procedure
(define (string-prefix? prefix s)
  (define p-len (string-length prefix))
  (define s-len (string-length s))
  (if (< s-len p-len)
      #f ;; simple case
      (let loop ((i 0))
	(or (= i p-len)
	    (and (eqv? (string-ref prefix i) (string-ref s i))
		 (loop (+ i 1)))))))
)
