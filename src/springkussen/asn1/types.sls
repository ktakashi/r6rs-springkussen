;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/asn1/types.sls - ASN.1 DER/BER types
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
(library (springkussen asn1 types)
    (export asn1-object?
	    asn1-encodable-object?
	    (rename (asn1-encodable-object <asn1-encodable-object>))
	    asn1-encodable-object->asn1-object

	    asn1-simple-object? asn1-simple-object-value
	    
	    BOOLEAN
	    der-boolean? make-der-boolean
	    (rename (asn1-simple-object-value der-boolean-value))
	    
	    INTEGER
	    der-integer? make-der-integer
	    (rename (asn1-simple-object-value der-integer-value))

	    asn1-string? (rename (asn1-string <asn1-string>)
				 (asn1-simple-object-value asn1-string-value))
	    
	    BIT-STRING
	    der-bit-string? make-der-bit-string
	    (rename (asn1-simple-object-value der-bit-string-value))
	    der-bit-string-padding-bits

	    OCTET-STRING
	    der-octet-string? make-der-octet-string
	    (rename (asn1-simple-object-value der-octet-string-value))

	    NULL
	    der-null? (rename (%make-der-null make-der-null))
	    
	    OBJECT-IDENTIFIER
	    der-object-identifier? make-der-object-identifier
	    (rename (asn1-simple-object-value der-object-identifier-value))
	    
	    EXTERNAL
	    der-external? make-der-external
	    der-external-dierct-reference
	    der-external-indierct-reference
	    der-external-data-value-descriptor
	    der-external-encoding
	    
	    ENUMERATED
	    der-enumerated? make-der-enumerated
	    (rename (asn1-simple-object-value der-enumerated-value))

	    SEQUENCE
	    SEQUENCE-OF
	    asn1-collection? asn1-collection-elements
	    der-sequence? make-der-sequence
	    (rename (asn1-collection-elements der-sequence-elements))
	    
	    SET
	    SET-OF
	    der-set? make-der-set
	    (rename (asn1-collection-elements der-set-elements))
	    
	    NUMERIC-STRING
	    der-numeric-string? make-der-numeric-string
	    (rename (asn1-simple-object-value der-numeric-string-value))
	    
	    PRINTABLE-STRING
	    der-printable-string? make-der-printable-string
	    (rename (asn1-simple-object-value der-printable-string-value))

	    T61-STRING
	    der-t61-string? make-der-t61-string
	    (rename (asn1-simple-object-value der-t61-string-value))

	    VIDEOTEX-STRING
	    der-videotex-string? make-der-videotex-string
	    (rename (asn1-simple-object-value der-videotex-string-value))

	    IA5-STRING
	    der-ia5-string? make-der-ia5-string
	    (rename (asn1-simple-object-value der-ia5-string-value))
	    
	    UTC-TIME
	    der-utc-time? make-der-utc-time
	    (rename (asn1-simple-object-value der-utc-time-value))

	    GENERALIZED-TIME
	    der-generalized-time? make-der-generalized-time
	    (rename (asn1-simple-object-value der-generalized-time-value))

	    GRAPHIC-STRING
	    der-graphic-string? make-der-graphic-string
	    (rename (asn1-simple-object-value der-graphic-string-value))

	    VISIBLE-STRING
	    der-visible-string? make-der-visible-string
	    (rename (asn1-simple-object-value der-visible-string-value))

	    GENERAL-STRING
	    der-general-string? make-der-general-string
	    (rename (asn1-simple-object-value der-general-string-value))

	    UNIVERSAL-STRING
	    der-universal-string? make-der-universal-string
	    (rename (asn1-simple-object-value der-universal-string-value))

	    BMP-STRING
	    der-bmp-string? make-der-bmp-string
	    (rename (asn1-simple-object-value der-bmp-string-value))

	    UTF8-STRING
	    der-utf8-string? make-der-utf8-string
	    (rename (asn1-simple-object-value der-utf8-string-value))

	    CONSTRUCTED

	    APPLICATION
	    der-application-specific? make-der-application-specific
	    der-application-specific-constructed?
	    der-application-specific-tag
	    der-application-specific-octets

	    TAGGED
	    der-tagged-object? make-der-tagged-object
	    der-tagged-object-tag-no
	    der-tagged-object-explicit? der-tagged-object-obj

	    )
    (import (rnrs)
	    (springkussen conditions))

(define BOOLEAN			#x01)	;
(define INTEGER			#x02)	;
(define BIT-STRING		#x03)	;
(define OCTET-STRING		#x04)	;
(define NULL			#x05)	;
(define OBJECT-IDENTIFIER	#x06)	;
(define EXTERNAL		#x08)	;
(define ENUMERATED		#x0a)	;
(define SEQUENCE		#x10)	;
(define SEQUENCE-OF		#x10)	; for completeness
(define SET			#x11)	;
(define SET-OF			#x11)	; for completeness

(define NUMERIC-STRING		#x12)	;
(define PRINTABLE-STRING	#x13)	;
(define T61-STRING		#x14)	;
(define VIDEOTEX-STRING		#x15)	;
(define IA5-STRING		#x16)	;
(define UTC-TIME		#x17)	;
(define GENERALIZED-TIME	#x18)	;
(define GRAPHIC-STRING		#x19)
(define VISIBLE-STRING		#x1a)
(define GENERAL-STRING		#x1b)
(define UNIVERSAL-STRING	#x1c)
(define BMP-STRING		#x1e)
(define UTF8-STRING		#x0c)

(define CONSTRUCTED		#x20)	;
(define APPLICATION		#x40)	;
(define TAGGED			#x80)	;

;; Abstract record type
(define-record-type asn1-object)
(define-record-type asn1-encodable-object
  (parent asn1-object)
  (fields converter))
(define (asn1-encodable-object->asn1-object asn1-encodable)
  ((asn1-encodable-object-converter asn1-encodable) asn1-encodable))

;; Simple value
(define-record-type asn1-simple-object
  (parent asn1-object)
  (fields value))

;; Boolean
(define-record-type der-boolean
  (parent asn1-simple-object))

;; Integer
(define-record-type der-integer
  (parent asn1-simple-object))

;; String (except octet string)
(define-record-type asn1-string
  (parent asn1-simple-object))

;; Bit string
(define-record-type der-bit-string
  (parent asn1-string)
  (fields padding-bits)
  (protocol (lambda (n)
	      (case-lambda
	       ((v) ((n v) 0))
	       ((v pad) ((n v) pad))))))

;; Octet string (chunk of bytes, it's binary data)
(define-record-type der-octet-string
  (parent asn1-simple-object))

;; Der null
(define-record-type der-null
  (parent asn1-object))
(define *der-null* (make-der-null))
(define (%make-der-null) *der-null*)

;; Der object identifier
(define-record-type der-object-identifier
  (parent asn1-simple-object))

;; Der external
(define-record-type der-external
  (parent asn1-object)
  (fields dierct-reference
	  indierct-reference
	  data-value-descriptor
	  encoding))

;; Der enumerated
(define-record-type der-enumerated
  (parent asn1-simple-object))

;; Collection
(define-record-type asn1-collection
  (parent asn1-object)
  (fields (mutable elements)))

;; Sequence
(define-record-type der-sequence
  (parent asn1-collection))

;; Set
(define-record-type der-set
  (parent asn1-collection))

;; Numeric string
(define-record-type der-numeric-string
  (parent asn1-string)
  ;; Maybe we should validate?
  )

;; Printable string
(define-record-type der-printable-string
  (parent asn1-string))

;; T61 string
(define-record-type der-t61-string
  (parent asn1-string))

;; Videotex string
(define-record-type der-videotex-string
  (parent asn1-string))

;; IA5-STRING
(define-record-type der-ia5-string
  (parent asn1-string))

;; UTC time (yyyyMMddhhmmssZ)
(define-record-type der-utc-time
  ;; Should we check the format?
  (parent asn1-simple-object))

;; Generalized-Time
(define-record-type der-generalized-time
  ;; Should we check the format?
  (parent asn1-simple-object))

;; Graphic string
(define-record-type der-graphic-string
  (parent asn1-string))

;; Visible-String
(define-record-type der-visible-string
  (parent asn1-string))

;; General-String
(define-record-type der-general-string
  (parent asn1-string))

;; UNIVERSAL-STRING
(define-record-type der-universal-string
  (parent asn1-string))

;; BMP-STRING
(define-record-type der-bmp-string
  (parent asn1-string))

;; UTF8-STRING
(define-record-type der-utf8-string
  (parent asn1-string))

;; Application specific
(define-record-type der-application-specific
  (parent asn1-object)
  (fields constructed? tag octets))

;; Tagged object
(define-record-type der-tagged-object
  (parent asn1-object)
  (fields tag-no explicit? obj))

)
