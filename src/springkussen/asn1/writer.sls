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
	    (springkussen conditions)
	    (springkussen misc bytevectors))

(define write-asn1-object
  (case-lambda
   ((asn1-object) (write-asn1-object asn1-object (current-output-port)))
   ((asn1-object output)
    (cond ((der-boolean? asn1-object)
	   (write-der-boolean asn1-object output))
	  ((der-integer? asn1-object)
	   (write-der-integer asn1-object output))
	  ((der-bit-string? asn1-object)
	   (write-der-bit-string asn1-object output))
	  ((der-octet-string? asn1-object)
	   (write-der-octet-string asn1-object output))
	  ((der-null? asn1-object)
	   (write-der-null asn1-object output))
	  ((der-object-identifier? asn1-object)
	   (write-der-object-identifier asn1-object output))
	  ((der-external? asn1-object)
	   (write-der-external asn1-object output))
	  ((der-enumerated? asn1-object)
	   (write-der-enumerated asn1-object output))
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

(define (asn1-string->string as) "not yet")


;; Boolean
(define (write-der-boolean db output)
  (write-der-encoded BOOLEAN
		     (make-bytevector 1 (if (der-boolean-value db) #xFF 0))
		     output))

;; Integer
(define (write-der-integer di output)
  (let ((v (der-integer-value di)))
    (write-der-encoded INTEGER
		       (sinteger->bytevector v (endianness big))
		       output)))

;; Bit string
(define (write-der-bit-string dbs output)
  (let* ((value (der-bit-string-value dbs))
	 (len (bytevector-length value))
	 (bytes (make-bytevector (+ len 1) (der-bit-string-padding-bits dbs))))
    (bytevector-copy! value 0 bytes 1 len)
    (write-der-encoded BIT-STRING bytes output)))

;; Octet string
(define (write-der-octet-string dos output)
  (write-der-encoded OCTET-STRING (der-octet-string-value dos) output))

;; Der null
(define (write-der-null asn1-object output)
  (write-der-encoded NULL #vu8() output))

;; Object identifier
(define (write-der-object-identifier doi output)
  (define (->oid-bytevector oid)
    (define oid-length (string-length oid))
    (define (oid-token oid s)
      ;; we use string-ref, it's R6RS, so should O(1)
      (let loop ((i s) (l '()))
	(if (= oid-length i)
	    (values (string->number (list->string (reverse l))) i)
	    (let ((v (string-ref oid i)))
	      (if (eqv? v #\.)
		  (values (string->number (list->string (reverse l))) (+ i 1))
		  (loop (+ i 1) (cons v l)))))))
    (define (write-field n out)
      (let ((byte-count (div (+ (bitwise-length n) 6) 7)))
	(if (zero? byte-count) (put-u8 out 0)
	    (let ((tmp (make-bytevector byte-count 0)))
	      (do ((i (- byte-count 1) (- i 1))
		   (n n (bitwise-arithmetic-shift n -7)))
		  ((< i 0)
		   (let* ((j (- byte-count 1))
			  (v (bytevector-u8-ref tmp j)))
		     (bytevector-u8-set! tmp j (bitwise-and v #x7F))
		     (put-bytevector out tmp)))
		(bytevector-u8-set! tmp i
		 (bitwise-ior (bitwise-and n #x7F) #x80)))))))
	      
    (let*-values (((out e) (open-bytevector-output-port))
		  ;; The first 2 numbers will be encoded into one byte
		  ((n1 i) (oid-token oid 0))
		  ((n2 i) (oid-token oid i)))
      (write-field (+ (* n1 40) n2) out)
      (let loop ((i i))
	(if (= i oid-length)
	    (e)
	    (let-values (((n i) (oid-token oid i)))
	      (write-field n out)
	      (loop i))))))
  (write-der-encoded OBJECT-IDENTIFIER
   (->oid-bytevector (der-object-identifier-value doi))
   output))

;; External
(define (write-der-external de output)
  (let ((dr (der-external-dierct-reference de))
	(idr (der-external-indierct-reference de))
	(dvd (der-external-data-value-descriptor de))
	(obj (der-external-encoding de)))
    (let-values (((out e) (open-bytevector-output-port)))
      (when dr (write-asn1-object (make-der-object-identifier dr) out))
      (when idr (write-asn1-object (make-der-integer idr) out))
      (when dvd (write-asn1-object dvd out))
      (write-asn1-object obj out)
      (write-der-encoded CONSTRUCTED EXTERNAL (e) output))))

;; Enumerated
(define (write-der-enumerated de output)
  (write-der-encoded ENUMERATED
   (sinteger->bytevector (der-enumerated-value de) (endianness big)) output))

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

