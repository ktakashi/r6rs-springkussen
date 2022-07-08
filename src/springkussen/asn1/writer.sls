;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/asn1/writer.sls - ASN.1 DER/BER writer
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
(library (springkussen asn1 writer)
    (export write-asn1-object
	    asn1-object->bytevector
	    )
    (import (rnrs)
	    (springkussen asn1 types)
	    (springkussen conditions))

(define write-asn1-object
  (case-lambda
   ((asn1-object) (write-asn1-object asn1-object (current-output-port)))
   ((asn1-object output)
    (cond ((der-boolean? asn1-object)
	   (write-der-boolean asn1-object output))
	  ((der-sequence? asn1-object)
	   (write-der-sequence asn1-object output))
	  ((der-set? asn1-object)
	   (write-der-set asn1-object output))
	  ((der-application-specific? asn1-object)
	   (write-der-application-specific asn1-object output))
	  ((der-tagged-object? asn1-object)
	   (write-der-tagged-object asn1-object output))	  
	  ((asn1-encodable-object? asn1-object)
	   ((asn1-encodable-object-writer asn1-object) asn1-object output))
	  (else
	   (springkussen-assertion-violation 'write-asn1-object
	    "Unknown ASN.1 object" asn1-object))))))

(define (asn1-object->bytevector asn1-object)
  (let-values (((out e) (open-bytevector-output-port)))
    (write-asn1-object asn1-object out)
    (e)))

;; Boolean
(define (write-der-boolean db output)
  (write-der-encoded BOOLEAN
		     (make-bytevector 1 (if (der-boolean-value db) #xFF 0))
		     output))

;; Application specific
(define (write-der-application-specific dap output)
  (write-der-encoded 
   (if (der-application-specific-constructed? dap)
       (bitwise-ior CONSTRUCTED APPLICATION)
       APPLICATION)
   (der-application-specific-tag dap)
   (der-application-specific-octets dap)
   output))

;; Tagged object
(define (write-der-tagged-object dto output)
  (let ((obj (der-tagged-object-obj dto)))
    (if obj
	(let ((bytes (asn1-object->bytevector obj)))
	  (if (der-tagged-object-explicit? dto)
	      (write-der-encoded (bitwise-ior CONSTRUCTED TAGGED)
				 (der-tagged-object-tag-no dto)
				 bytes output)
	      (let ((flag (cond ((not (zero? (bitwise-and
					      (bytevector-u8-ref bytes 0)
					      CONSTRUCTED)))
				 (bitwise-ior CONSTRUCTED TAGGED))
				(else TAGGED))))
		(write-der-tag flag (der-tagged-object-tag-no dto) output)
		(put-bytevector output bytes 1
				(- (bytevector-length bytes) 1)))))
	(write-der-encoded (bitwise-ior CONSTRUCTED TAGGED)
			   (der-tagged-object-tag-no dto) #vu8() output))))

;; DER sequence
(define (make-collection-encoder tag)
  (lambda (asn1-object output)
    (write-der-encoded
     (bitwise-ior tag CONSTRUCTED)
     (let-values (((out e) (open-bytevector-output-port)))
       (for-each (lambda (e) (write-asn1-object e out))
		 (der-sequence-elements asn1-object))
       (e))
     output)))
(define write-der-sequence (make-collection-encoder SEQUENCE))
(define write-der-set (make-collection-encoder SET))

(define write-der-encoded
  (case-lambda
   ((tag bytes output)
    (put-u8 output tag)
    (write-der-length (bytevector-length bytes) output)
    (put-bytevector output bytes))
   ((flags tag-no bytes output)
    (write-der-tag flags tag-no output)
    (write-der-length (bytevector-length bytes) output)
    (put-bytevector output bytes))))

(define rash bitwise-arithmetic-shift-right)
(define (write-der-tag flags tag-no p)
  (cond ((< tag-no 31) (put-u8 p (bitwise-ior flags tag-no)))
	(else
	 (put-u8 p (bitwise-ior flags #x1f))
	 (if (< tag-no 128)
	     (put-u8 p tag-no)
	     (let ((stack (make-bytevector 5))
		   (pos 4))
	       (bytevector-u8-set! stack pos (bitwise-and tag-no #x7f))
	       (let loop ((ntag-no (rash tag-no 7))
			  (pos (- pos 1)))
		 (bytevector-u8-set! stack pos 
				     (bitwise-ior (bitwise-and ntag-no #x7f)
						  #x80))
		 (if (> ntag-no 127)
		     (loop (rash ntag-no 7) (- pos 1))
		     (put-bytevector p stack pos))))))))

(define (write-der-length len p)
  (if (> len 127)
      (let ((size (do ((size 1 (+ size 1))
		       (val (rash len 8) (rash val 8)))
		      ((zero? val) size))))
	(put-u8 p (bitwise-ior size #x80))
	(do ((i (* (- size 1) 8) (- i 8)))
	    ((< i 0))
	  (put-u8 p (bitwise-and (rash len i) #xff))))
      (put-u8 p len)))

)

