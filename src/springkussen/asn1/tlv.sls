;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/asn1/tlv.sls - TLV parser
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

;; TLV is not ASN.1 specific though there's not much proper location
;; to put, and this is the only one using this. So let's put it here.
#!r6rs
(library (springkussen asn1 tlv)
    (export make-tlv-parser)
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen misc bytevectors))

(define (make-tlv-parser builder)
  (define (parse-tlv-object-list in in-indefinite?)
    (let loop ((o (tlv-parser in in-indefinite?)) (r '()))
      (if o
	  (loop (tlv-parser in in-indefinite?) (cons o r))
	  (reverse r))))
  (define (handle-indefinite b tag in)
    (builder b tag (parse-tlv-object-list in #t) #t))
  (define (tlv-parser in in-indefinite?)
    (let ((b (get-u8 in)))
      (cond ((eof-object? b) #f)
	    ((and in-indefinite? (zero? b) (zero? (lookahead-u8 in)))
	     (get-u8 in) #f)
	    (else
	     (let-values (((tag constructed? len) (read-tag&length in b)))
	       (cond (len
		      (let ((data (get-bytevector-n in len)))
			(when (< (bytevector-length data) len)
			  (springkussen-error 'tlv-parser "Corrupted data"))
			(if constructed?
			    (builder b tag
			     (call-with-port (open-bytevector-input-port data)
			       (lambda (in)
				 (parse-tlv-object-list in in-indefinite?)))
			     #t)
			    (builder b tag data #f))))
		     ((not constructed?)
		      (springkussen-error 'tlv-parser "Indefinite length found"
					  tag))
		     (else (handle-indefinite b tag in))))))))
  (lambda (in) (tlv-parser in #f)))

(define (read-tag&length in b)
  (define (read-tag in b)
    (if (= (bitwise-and b #x1F) #x1F)
	(let-values (((out e) (open-bytevector-output-port)))
	  (put-u8 out b)
	  (let ((b2 (get-u8 in)))
	    (when (zero? (bitwise-and b2 #x7F))
	      (springkussen-error 'read-tag
	       "Corrupted stream - invalid high tag number found" b2))
	    (do ((b3 b2 (get-u8 in)))
		((or (eof-object? b3) (zero? (bitwise-and b3 #x80)))
		 (when (eof-object? b3)
		   (springkussen-error 'read-tag "EOF found inside tag value"))
		 (put-u8 out b3)
		 (e))
	      (put-u8 out b3))))
	(make-bytevector 1 b)))
  (define (read-length in)
    (let ((len (get-u8 in)))
      (when (eof-object? len)
	(springkussen-error 'read-tag "EOF found when length expected"))
      (cond ((= len #x80) #f) ;; indefinite length
	    ((zero? (bitwise-and len #x80)) len)
	    (else
	     (let* ((size (bitwise-and #x7F len))
		    (len-bytes (get-bytevector-n in size)))
	       ;; We might need to use bytevector->sinteger to detect
	       ;; negative number, which is not allowed
	       (bytevector->uinteger len-bytes (endianness big)))))))
	       
  (let ((tag (read-tag in b)))
    (values tag (not (zero? (bitwise-and #x20 b))) (read-length in))))

)

