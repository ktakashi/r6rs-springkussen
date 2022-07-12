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

	    asn1-string->string ;; unfortunately, this needs to be here

	    describe-asn1-object
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
	  ((der-numeric-string? asn1-object)
	   (write-der-numeric-string asn1-object output))
	  ((der-printable-string? asn1-object)
	   (write-der-printable-string asn1-object output))
	  ((der-t61-string? asn1-object)
	   (write-der-t61-string asn1-object output))
	  ((der-videotex-string? asn1-object)
	   (write-der-videotex-string asn1-object output))
	  ((der-ia5-string? asn1-object)
	   (write-der-ia5-string asn1-object output))
	  ((der-utc-time? asn1-object)
	   (write-der-utc-time asn1-object output))
	  ((der-generalized-time? asn1-object)
	   (write-der-generalized-time asn1-object output))
	  ((der-graphic-string? asn1-object)
	   (write-der-graphic-string asn1-object output))
	  ((der-visible-string? asn1-object)
	   (write-der-visible-string asn1-object output))
	  ((der-general-string? asn1-object)
	   (write-der-general-string asn1-object output))
	  ((der-universal-string? asn1-object)
	   (write-der-universal-string asn1-object output))
	  ((der-bmp-string? asn1-object)
	   (write-der-bmp-string asn1-object output))
	  ((der-utf8-string? asn1-object)
	   (write-der-utf8-string asn1-object output))
	  ((der-application-specific? asn1-object)
	   (write-der-application-specific asn1-object output))
	  ((der-tagged-object? asn1-object)
	   (write-der-tagged-object asn1-object output))
	  ((der-unknown-tag? asn1-object)
	   (write-der-unknown-tag asn1-object output))
	  ((asn1-encodable-object? asn1-object)
	   (let ((converted (asn1-encodable-object->asn1-object asn1-object)))
	     (write-asn1-object converted output)))
	  (else
	   (springkussen-assertion-violation 'write-asn1-object
	    "Unknown ASN.1 object" asn1-object))))))

(define (asn1-object->bytevector asn1-object)
  (let-values (((out e) (open-bytevector-output-port)))
    (write-asn1-object asn1-object out)
    (e)))

(define *table* "0123456789ABCDEF")
(define (asn1-string->string as)
  (unless (asn1-string? as)
    (springkussen-assertion-violation 'asn1-string->string
				      "ASN.1 string is required" as))
  (if (der-bit-string? as)
      ;; Bit string requires a bit of treatment
      (let ((encoded (asn1-object->bytevector as)))
	(let-values (((out e) (open-string-output-port)))
	  (do ((i 0 (+ i 1)) (len (bytevector-length encoded)))
	      ((= i len) (e))
	    (let* ((b (bytevector-u8-ref encoded i))
		   (c (bitwise-and (bitwise-arithmetic-shift b -4) #xF)))
	      (put-char out (string-ref *table* c))
	      (put-char out (string-ref *table* (bitwise-and b #xF)))))))
      (asn1-string-value as)))

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

;; Numeric string
(define (write-der-numeric-string dns output)
  (write-der-encoded NUMERIC-STRING
   (string->utf8 (der-numeric-string-value dns)) output))

;; Printable string
(define (write-der-printable-string dps output)
  (write-der-encoded PRINTABLE-STRING
   (string->utf8 (der-printable-string-value dps)) output))

;; T61 string
(define (write-der-t61-string dts output)
  (write-der-encoded T61-STRING
   (string->utf8 (der-t61-string-value dts)) output))

;; Videotex string
(define (write-der-videotex-string dvs output)
  (write-der-encoded VIDEOTEX-STRING
   (string->utf8 (der-videotex-string-value dvs)) output))

;; IA5 string
(define (write-der-ia5-string dvs output)
  (write-der-encoded IA5-STRING
   (string->bytevector (der-ia5-string-value dvs)
		       (make-transcoder (latin-1-codec))) output))

;; UTC time
(define (write-der-utc-time dut output)
  (write-der-encoded UTC-TIME
   (string->utf8 (der-utc-time-value dut)) output))

;; Generalized time
(define (write-der-generalized-time dgt output)
  (write-der-encoded GENERALIZED-TIME
   (string->utf8 (der-generalized-time-value dgt)) output))

;; Graphic string
(define (write-der-graphic-string dgs output)
  (write-der-encoded GRAPHIC-STRING
   (string->utf8 (der-graphic-string-value dgs)) output))

;; Visible string
(define (write-der-visible-string dvs output)
  (write-der-encoded VISIBLE-STRING
   (string->utf8 (der-visible-string-value dvs)) output))

;; General string
(define (write-der-general-string dvs output)
  (write-der-encoded GENERAL-STRING
   (string->utf8 (der-general-string-value dvs)) output))

;; UNIVERSAL-STRING
(define (write-der-universal-string dvs output)
  (write-der-encoded UNIVERSAL-STRING
   (string->utf8 (der-universal-string-value dvs)) output))

;; BMP string
(define (write-der-bmp-string dvs output)
  (write-der-encoded BMP-STRING
   (string->utf8 (der-bmp-string-value dvs)) output))

;; UTF8 string
(define (write-der-utf8-string dvs output)
  (write-der-encoded UTF8-STRING
   (string->utf8 (der-utf8-string-value dvs)) output))

;; unknown tag
(define (write-der-unknown-tag dut output)
  (write-der-encoded (if (der-unknown-tag-constructed? dut)
			 CONSTRUCTED
			 0)
		     (der-unknown-tag-number dut)
		     (der-unknown-tag-data dut)
		     output))

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

(define (describe-asn1-object-rec asn1-object output indent)
  (define (put-indent)
    (do ((i 0 (+ i 1))) ((= i indent))
      (put-char output #\space)
      (put-char output #\space)))
  (define put-description 
    (case-lambda
     ((name obj)
      (put-indent)
      (display name output)
      (display ": " output)
      (put-datum output obj)
      (newline output))
     ((name)
      (put-indent)
      (display name output)
      (newline output))))
  (cond ((asn1-simple-object? asn1-object)
	 (put-description (record-type-name (record-rtd asn1-object))
			  (asn1-simple-object-value asn1-object)))
	((der-null? asn1-object) (put-description "der-null"))
	((asn1-collection? asn1-object)
	 (put-description (record-type-name (record-rtd asn1-object)))
	 (for-each (lambda (e) (describe-asn1-object-rec e output (+ indent 1)))
		   (asn1-collection-elements asn1-object)))
	((asn1-encodable-object? asn1-object)
	 (describe-asn1-object-rec
	  (asn1-encodable-object->asn1-object asn1-object) output indent))
	;; Okay, compount with annoying definitions
	((der-external? asn1-object)
	 (let ((dr (der-external-dierct-reference asn1-object))
	       (idr (der-external-indierct-reference asn1-object))
	       (dvd (der-external-data-value-descriptor asn1-object))
	       (obj (der-external-encoding asn1-object)))
	   (put-description "der-external")
	   (when dr
	     (put-indent) (put-indent) (display "direct-reference: " output)
	     (describe-asn1-object-rec (make-der-object-identifier dr)
				       output 0))
	   (when idr
	     (put-indent) (put-indent) (display "indirect-reference: " output)
	     (describe-asn1-object-rec (make-der-integer idr) output 0))
	   (when dvd
	     (put-indent) (put-indent)
	     (display "data-value-descriptor: " output)
	     (describe-asn1-object-rec dvd output (+ indent 3)))
	   (put-indent) (put-indent) (display "encoding: " output)
	   (describe-asn1-object-rec obj output (+ indent 3))))
	((der-tagged-object? asn1-object)
	 (put-indent) (display "der-tagged-object [" output)
	 (display (der-tagged-object-tag-no asn1-object) output)
	 (display "] " output)
	 (if (der-tagged-object-explicit? asn1-object)
	     (display "EXPLICIT " output)
	     (display "IMPLICIT " output))
	 (newline output)
	 (describe-asn1-object-rec (der-tagged-object-obj asn1-object)
				   output (+ indent 1)))
	((der-application-specific? asn1-object)
	 (put-indent) (display "der-application-specific [" output)
	 (display (der-application-specific-tag asn1-object) output)
	 (display "]" output)
	 (when (der-application-specific-constructed? asn1-object)
	   (display "CONSTRUCTED" output))
	 (display ":" output)
	 (put-datum output (der-application-specific-octets asn1-object))
	 (newline output))
	((der-unknown-tag? asn1-object)
	 (put-indent) (display "der-unknown-tag [" output)
	 (display (der-unknown-tag-number asn1-object) output)
	 (display "]" output)
	 (when (der-unknown-tag-constructed? asn1-object)
	   (display " CONSTRUCTED" output))
	 (display ":") (put-datum output (der-unknown-tag-data asn1-object))
	 (newline output))
	(else
	 (springkussen-assertion-violation 'describe-asn1-object
	   "Unknown ASN.1 object" asn1-object))))

(define describe-asn1-object
  (case-lambda
   ((asn1-object) (describe-asn1-object asn1-object (current-output-port)))
   ((asn1-object output) (describe-asn1-object-rec asn1-object output 0))))

)

