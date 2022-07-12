;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/asn1/reader.sls - ASN.1 DER/BER reader
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
(library (springkussen asn1 reader)
    (export read-asn1-object
	    bytevector->asn1-object)
    (import (rnrs)
	    (springkussen asn1 tlv)
	    (springkussen asn1 types)
	    (springkussen asn1 writer)
	    (springkussen conditions)
	    (springkussen misc bytevectors))

(define read-asn1-object
  (case-lambda
   (() (read-asn1-object (current-input-port)))
   ((in)
    (unless (and (binary-port? in) (input-port? in))
      (springkussen-assertion-violation 'read-asn1-object
					"Binary port required" in))
    (read-object in))))

(define (bytevector->asn1-object bv)
  (read-asn1-object (open-bytevector-input-port bv)))

(define (asn1-object-builder b tag-bv data constructed?)
  (define (convert-tag b tag)
    (let ((b2 (bitwise-and b #x1F)))
      (if (= b2 #x1F)
	  (bytevector->uinteger tag (endianness big))
	  b2)))
  (define tag (convert-tag b tag-bv))
  (when (eof-object? data)
    (springkussen-error 'read-asn1-object "EOF found during reading data"))
  (cond ((not (zero? (bitwise-and b APPLICATION)))
	 (if constructed?
	     (make-der-application-specific constructed? tag
	      (asn1-object->bytevector (car data)))
	     (make-der-application-specific constructed? tag data)))
	((not (zero? (bitwise-and b TAGGED)))
	 (build-tagged-object tag data constructed?))
	(constructed?
	 (cond ((= tag OCTET-STRING)
		(springkussen-error 'read-asn1-object
				    "BER octet string is not yet supported"))
	       ((= tag SEQUENCE) (make-der-sequence data))
	       ((= tag SET) (make-der-set data))
	       ((= tag EXTERNAL) (build-der-external data))
	       ;; TODO do we handle constructed primitive data?
	       (else (make-der-unknown-tag #t tag data))))
	(else (create-primitive-der-object tag data))))

(define read-object (make-tlv-parser asn1-object-builder))

(define (build-tagged-object tag in constructed?)
  ;; TODO also BER?
  (cond (constructed?
	 (case (length in)
	   ((0) (make-der-tagged-object tag constructed? #f))
	   ((1) (make-der-tagged-object tag constructed? (car in)))
	   (else
	    (make-der-tagged-object tag constructed? (make-der-sequence in)))))
	((zero? (bytevector-length in))
	 (make-der-tagged-object tag constructed? #f))
	(else
	 (make-der-tagged-object tag constructed? (make-der-octet-string in)))))

(define (build-der-external odata)
  ;; data must be (? denotes optional)
  ;; oid? integer? asn1-object? tagged-object
  ;; we do a bit lazily here
  (let loop ((data odata) (dr #f) (idr #f) (dvd #f) (obj #f))
    (cond ((null? data)
	   (unless obj
	     (springkussen-error 'read-object "Corrupted DER external" odata))
	   (make-der-external dr idr dvd obj))
	  ((der-object-identifier? (car data))
	   (when dr
	     (springkussen-error 'read-object "Corrupted DER external" odata))
	   (loop (cdr data) (der-object-identifier-value (car data))
		 idr dvd obj))
	  ((der-integer? (car data))
	   (when idr
	     (springkussen-error 'read-object "Corrupted DER external" odata))
	   (loop (cdr data) dr (der-integer-value (car data)) dvd obj))
	  ((der-tagged-object? (car data))
	   (when (or obj (not (null? (cdr data))))
	     (springkussen-error 'read-object "Corrupted DER external" odata))
	   (loop (cdr data) dr idr dvd (car data)))
	  ((asn1-object? (car data))
	   (when dvd
	     (springkussen-error 'read-object "Corrupted DER external" odata))
	   (loop (cdr data) dr idr (car data) obj))
	  (else
	   (springkussen-error  'read-object "Corrupted DER external" odata)))))

(define (create-primitive-der-object tag-no bytes)
  (let ((ctr (cond ((assv tag-no *constructors*) => cdr)
		   (else #f))))
    (if ctr
	(ctr bytes)
	(make-der-unknown-tag #f tag-no bytes))))
(define *constructors* 
  `((,BIT-STRING 	. ,bytevector->der-bit-string)
    (,BMP-STRING 	. ,bytevector->der-bmp-string)
    (,BOOLEAN    	. ,bytevector->der-boolean)
    (,ENUMERATED 	. ,bytevector->der-enumerated)
    (,GENERALIZED-TIME  . ,bytevector->der-generalized-time)
    (,GENERAL-STRING    . ,bytevector->der-general-string)
    (,IA5-STRING        . ,bytevector->der-ia5-string)
    (,INTEGER           . ,bytevector->der-integer)
    (,NULL              . ,(lambda (_) (make-der-null)))
    (,NUMERIC-STRING    . ,bytevector->der-numeric-string)
    (,OBJECT-IDENTIFIER . ,bytevector->der-object-identifier)
    (,OCTET-STRING      . ,make-der-octet-string)
    (,PRINTABLE-STRING  . ,bytevector->der-printable-string)
    (,GRAPHIC-STRING    . ,bytevector->der-graphic-string)
    (,T61-STRING        . ,bytevector->der-t61-string)
    (,UNIVERSAL-STRING  . ,bytevector->der-universal-string)
    (,UTC-TIME          . ,bytevector->der-utc-time)
    (,UTF8-STRING       . ,bytevector->der-utf8-string)
    (,VISIBLE-STRING    . ,bytevector->der-visible-string)
    (,VIDEOTEX-STRING   . ,bytevector->der-videotex-string)))

)
	    
