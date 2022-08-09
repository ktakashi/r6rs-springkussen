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
	    asn1-object=?
	    
	    asn1-encodable-object?
	    (rename (asn1-encodable-object <asn1-encodable-object>))
	    asn1-encodable-object->asn1-object
	    simple-asn1-encodable-object->der-sequence
	    simple-asn1-encodable-object->der-set

	    asn1-simple-object? asn1-simple-object-value
	    
	    BOOLEAN
	    der-boolean? make-der-boolean
	    (rename (asn1-simple-object-value der-boolean-value))
	    bytevector->der-boolean
	    
	    INTEGER
	    der-integer? make-der-integer
	    (rename (asn1-simple-object-value der-integer-value))
	    bytevector->der-integer
	    
	    asn1-string? (rename (asn1-string <asn1-string>)
				 (asn1-simple-object-value asn1-string-value))
	    
	    BIT-STRING
	    der-bit-string? make-der-bit-string
	    (rename (asn1-simple-object-value der-bit-string-value))
	    der-bit-string-padding-bits
	    bytevector->der-bit-string

	    OCTET-STRING
	    der-octet-string? make-der-octet-string
	    (rename (asn1-simple-object-value der-octet-string-value))

	    NULL
	    der-null? (rename (%make-der-null make-der-null))
	    
	    OBJECT-IDENTIFIER
	    der-object-identifier? make-der-object-identifier
	    (rename (asn1-simple-object-value der-object-identifier-value))
	    bytevector->der-object-identifier
	    
	    EXTERNAL
	    der-external? make-der-external
	    der-external-dierct-reference
	    der-external-indierct-reference
	    der-external-data-value-descriptor
	    der-external-encoding
	    
	    ENUMERATED
	    der-enumerated? make-der-enumerated
	    (rename (asn1-simple-object-value der-enumerated-value))
	    bytevector->der-enumerated

	    SEQUENCE
	    SEQUENCE-OF
	    asn1-collection? asn1-collection-elements
	    asn1-collection:find-tagged-object

	    der-sequence? make-der-sequence
	    (rename (der-sequence <der-sequence>)
		    (%der-sequence der-sequence)
		    (asn1-collection-elements der-sequence-elements))
	    der-sequence-of?
	    
	    SET
	    SET-OF
	    der-set? make-der-set
	    (rename (der-set <der-set>)
		    (%der-set der-set)
		    (asn1-collection-elements der-set-elements))
	    der-set-of?
	    
	    NUMERIC-STRING
	    der-numeric-string? make-der-numeric-string
	    (rename (asn1-simple-object-value der-numeric-string-value))
	    bytevector->der-numeric-string
	    
	    PRINTABLE-STRING
	    der-printable-string? make-der-printable-string
	    (rename (asn1-simple-object-value der-printable-string-value))
	    bytevector->der-printable-string

	    T61-STRING
	    der-t61-string? make-der-t61-string
	    (rename (asn1-simple-object-value der-t61-string-value))
	    bytevector->der-t61-string

	    VIDEOTEX-STRING
	    der-videotex-string? make-der-videotex-string
	    (rename (asn1-simple-object-value der-videotex-string-value))
	    bytevector->der-videotex-string

	    IA5-STRING
	    der-ia5-string? make-der-ia5-string
	    (rename (asn1-simple-object-value der-ia5-string-value))
	    bytevector->der-ia5-string
	    
	    UTC-TIME
	    der-utc-time? make-der-utc-time
	    (rename (asn1-simple-object-value der-utc-time-value))
	    bytevector->der-utc-time

	    GENERALIZED-TIME
	    der-generalized-time? make-der-generalized-time
	    (rename (asn1-simple-object-value der-generalized-time-value))
	    bytevector->der-generalized-time

	    GRAPHIC-STRING
	    der-graphic-string? make-der-graphic-string
	    (rename (asn1-simple-object-value der-graphic-string-value))
	    bytevector->der-graphic-string

	    VISIBLE-STRING
	    der-visible-string? make-der-visible-string
	    (rename (asn1-simple-object-value der-visible-string-value))
	    bytevector->der-visible-string

	    GENERAL-STRING
	    der-general-string? make-der-general-string
	    (rename (asn1-simple-object-value der-general-string-value))
	    bytevector->der-general-string

	    UNIVERSAL-STRING
	    der-universal-string? make-der-universal-string
	    (rename (asn1-simple-object-value der-universal-string-value))
	    bytevector->der-universal-string

	    BMP-STRING
	    der-bmp-string? make-der-bmp-string
	    (rename (asn1-simple-object-value der-bmp-string-value))
	    bytevector->der-bmp-string

	    UTF8-STRING
	    der-utf8-string? make-der-utf8-string
	    (rename (asn1-simple-object-value der-utf8-string-value))
	    bytevector->der-utf8-string

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

	    der-unknown-tag? make-der-unknown-tag
	    der-unknown-tag-constructed? der-unknown-tag-number
	    der-unknown-tag-data
	    )
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen misc bytevectors)
	    (springkussen misc lambda)
	    (springkussen misc record))

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

(define/typed (simple-asn1-encodable-object->der-sequence
	       (asn1-encodable asn1-encodable-object?))
  (let* ((rtd (record-rtd asn1-encodable))
	 (accs (record-type-all-field-accessors rtd)))
    (make-der-sequence 
     (filter values (map (lambda (acc) (acc asn1-encodable)) (cdr accs))))))
(define/typed (simple-asn1-encodable-object->der-set
	       (asn1-encodable asn1-encodable-object?))
  (let* ((rtd (record-rtd asn1-encodable))
	 (accs (record-type-all-field-accessors rtd)))
    (make-der-set
     (filter values (map (lambda (acc) (acc asn1-encodable)) (cdr accs))))))


;; Simple value
(define-record-type asn1-simple-object
  (parent asn1-object)
  (fields value))

;; Boolean
(define-record-type der-boolean
  (parent asn1-simple-object))
(define (bytevector->der-boolean bv)
  (unless (= (bytevector-length bv) 1)
    (springkussen-assertion-violation 'bytevector->der-boolean
				      "Bytevector length must be one" bv))
  (make-der-boolean (not (zero? (bytevector-u8-ref bv 0)))))

;; Integer
(define-record-type der-integer
  (parent asn1-simple-object))
(define (bytevector->der-integer bv)
  (make-der-integer (bytevector->sinteger bv (endianness big))))

;; String (except octet string)
(define-record-type asn1-string
  (parent asn1-simple-object))
(define make-bytevector->asn1-string
  (case-lambda
   ((ctr) (lambda (bv) (ctr (utf8->string bv))))
   ((ctr transcoder) (lambda (bv) (ctr (bytevector->string bv transcoder))))))

;; Bit string
(define-record-type der-bit-string
  (parent asn1-string)
  (fields padding-bits)
  (protocol (lambda (n)
	      (case-lambda
	       ((v) ((n v) 0))
	       ((v pad) ((n v) pad))))))

(define (bytevector->der-bit-string bytes)
  (let ((len (bytevector-length bytes)))
    (when (< len 1)
      (springkussen-assertion-violation 'create-primitive-der-object
					"truncated BIT STRING detected"))
    (let ((pad (bytevector-u8-ref bytes 0))
	  (data (make-bytevector (- len 1))))
      (bytevector-copy! bytes 1 data 0 (- len 1))
      (make-der-bit-string data pad))))

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
(define (bytevector->der-object-identifier bv)
  (define len (bytevector-length bv))
  (let-values (((out e) (open-string-output-port)))
    (let loop ((value 0) (first 0) (i 0))
      (if (= i len)
	  (make-der-object-identifier (e))
	  (let* ((b (bitwise-and (bytevector-u8-ref bv i) #xFF))
		 (value (+ (* value 128) (bitwise-and b #x7F))))
	    (if (zero? (bitwise-and b #x80))
		(let ((value (if first
				 (case (div value 40)
				   ((0) (put-char out #\0) value)
				   ((1) (put-char out #\1) (- value 40))
				   (else (put-char out #\2) (- value 80)))
				 value)))
		  (put-char out #\.)
		  (put-string out (number->string value))
		  (loop 0 #f (+ i 1)))
		(loop value first (+ i 1))))))))
	

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
(define (bytevector->der-enumerated bv)
  (make-der-enumerated (bytevector->sinteger bv (endianness big))))

;; Collection
(define-record-type asn1-collection
  (parent asn1-object)
  (fields (mutable elements)))

(define/typed (asn1-collection:find-tagged-object
	       (collection asn1-collection?) (tag-no integer?))
  (find (lambda (o)
	  (and (der-tagged-object? o)
	       (= (der-tagged-object-tag-no o) tag-no)))
	(asn1-collection-elements collection)))

;; Sequence
(define-record-type der-sequence
  (parent asn1-collection))
(define (%der-sequence . lis) (make-der-sequence lis))
(define (der-sequence-of? pred)
  (lambda (v)
    (and (der-sequence? v)
	 (for-all pred (asn1-collection-elements v)))))
;; Set
(define-record-type der-set
  (parent asn1-collection))
(define (%der-set . lis) (make-der-set lis))
(define (der-set-of? pred)
  (lambda (v)
    (and (der-set? v)
	 (for-all pred (asn1-collection-elements v)))))

;; Numeric string
(define-record-type der-numeric-string
  (parent asn1-string)
  ;; Maybe we should validate?
  )
(define bytevector->der-numeric-string
  (make-bytevector->asn1-string make-der-numeric-string))


;; Printable string
(define-record-type der-printable-string
  (parent asn1-string))
(define bytevector->der-printable-string
  (make-bytevector->asn1-string make-der-printable-string))

;; T61 string
(define-record-type der-t61-string
  (parent asn1-string))
(define bytevector->der-t61-string
  (make-bytevector->asn1-string make-der-t61-string))

;; Videotex string
(define-record-type der-videotex-string
  (parent asn1-string))
(define bytevector->der-videotex-string
  (make-bytevector->asn1-string make-der-videotex-string))

;; IA5-STRING
(define-record-type der-ia5-string
  (parent asn1-string))
(define bytevector->der-ia5-string
  (make-bytevector->asn1-string make-der-ia5-string))

;; UTC time (yyyyMMddhhmmssZ)
(define-record-type der-utc-time
  ;; Should we check the format?
  (parent asn1-simple-object))
(define bytevector->der-utc-time
  (make-bytevector->asn1-string make-der-utc-time))

;; Generalized-Time
(define-record-type der-generalized-time
  ;; Should we check the format?
  (parent asn1-simple-object))
(define bytevector->der-generalized-time
  (make-bytevector->asn1-string make-der-generalized-time))

;; Graphic string
(define-record-type der-graphic-string
  (parent asn1-string))
(define bytevector->der-graphic-string
  (make-bytevector->asn1-string make-der-graphic-string))

;; Visible-String
(define-record-type der-visible-string
  (parent asn1-string))
(define bytevector->der-visible-string
  (make-bytevector->asn1-string make-der-visible-string))

;; General-String
(define-record-type der-general-string
  (parent asn1-string))
(define bytevector->der-general-string
  (make-bytevector->asn1-string make-der-general-string))

;; UNIVERSAL-STRING
(define-record-type der-universal-string
  (parent asn1-string))
(define bytevector->der-universal-string
  (make-bytevector->asn1-string make-der-universal-string))

;; BMP-STRING
(define-record-type der-bmp-string
  (parent asn1-string))
(define bytevector->der-bmp-string
  (make-bytevector->asn1-string make-der-bmp-string))

;; UTF8-STRING
(define-record-type der-utf8-string
  (parent asn1-string))
(define bytevector->der-utf8-string
  (make-bytevector->asn1-string make-der-utf8-string))

;; Application specific
(define-record-type der-application-specific
  (parent asn1-object)
  (fields constructed? tag octets))

;; Tagged object
(define-record-type der-tagged-object
  (parent asn1-object)
  (fields tag-no explicit? obj))

;; Unknown tag
(define-record-type der-unknown-tag
  (parent asn1-object)
  (fields constructed? number data))

(define (asn1-object=? a b)
  (cond ((eq? a b))
	;; Is this valid for R6RS?
	((and (asn1-object? a) (asn1-object? b)
	      (eq? (record-rtd a) (record-rtd b)))
	 (cond ((asn1-simple-object? a)
		(equal? (asn1-simple-object-value a)
			(asn1-simple-object-value b)))
	       ((asn1-encodable-object? a)
		(asn1-object=? (asn1-encodable-object->asn1-object a)
			       (asn1-encodable-object->asn1-object b)))
	       ((der-tagged-object? a)
		(and (eqv? (der-tagged-object-tag-no a)
			   (der-tagged-object-tag-no b))
		     (eqv? (der-tagged-object-explicit? a)
			   (der-tagged-object-explicit? b))
		     (asn1-object=? (der-tagged-object-obj a)
				    (der-tagged-object-obj b))))
	       ((der-application-specific? a)
		(and (eqv? (der-application-specific-constructed? a)
			   (der-application-specific-constructed? b))
		     (eqv? (der-application-specific-tag a)
			   (der-application-specific-tag b))
		     (equal? (der-application-specific-octets a)
			     (der-application-specific-octets b))))
	       ((asn1-collection? a)
		(and (= (length (asn1-collection-elements a))
			(length (asn1-collection-elements b)))
		     ;; TODO this doesn't apply to set...
		     (for-all asn1-object=?
			      (asn1-collection-elements a)
			      (asn1-collection-elements b))))
	       ((der-external? a)
		(let ((adr (der-external-dierct-reference a))
		      (aidr (der-external-indierct-reference a))
		      (advd (der-external-data-value-descriptor a))
		      (aobj (der-external-encoding a))
		      (bdr (der-external-dierct-reference b))
		      (bidr (der-external-indierct-reference b))
		      (bdvd (der-external-data-value-descriptor b))
		      (bobj (der-external-encoding b)))
		  (and (equal? adr bdr)
		       (eqv?  aidr bidr)
		       (or (and advd bdvd (asn1-object=? advd bdvd))
			   (and (not advd) (not bdvd)))
		       (asn1-object=? aobj bobj))))
	       ((der-unknown-tag? a)
		(and (eqv? (der-unknown-tag-constructed? a)
			   (der-unknown-tag-constructed? b))
		     (eqv? (der-unknown-tag-number a)
			   (der-unknown-tag-number b))
		     (equal? (der-unknown-tag-data a)
			     (der-unknown-tag-data b))))
	       (else #f)))
	(else #f)))

)
