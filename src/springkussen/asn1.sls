;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/asn1.sls - ASN.1 DER/BER APIs
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
(library (springkussen asn1)
    (export asn1-object?
	    asn1-object=?
	    
	    asn1-encodable-object? <asn1-encodable-object>
	    asn1-encodable-object->asn1-object
	    simple-asn1-encodable-object->der-sequence
	    simple-asn1-encodable-object->der-set
	    
	    asn1-simple-object? asn1-simple-object-value
	    
	    der-boolean? make-der-boolean der-boolean-value
	    bytevector->der-boolean
	    
	    der-integer? make-der-integer der-integer-value
	    bytevector->der-integer
	    
	    asn1-string? <asn1-string> asn1-string-value
	    
	    der-bit-string? make-der-bit-string
	    der-bit-string-value der-bit-string-padding-bits
	    bytevector->der-bit-string

	    der-octet-string? make-der-octet-string
	    der-octet-string-value

	    der-null? make-der-null 	    

	    der-object-identifier? make-der-object-identifier
	    der-object-identifier-value
	    bytevector->der-object-identifier
	    
	    der-external? make-der-external
	    der-external-direct-reference
	    der-external-indirect-reference
	    der-external-data-value-descriptor
	    der-external-encoding
	    
	    der-enumerated? make-der-enumerated der-enumerated-value
	    bytevector->der-enumerated

	    asn1-collection? asn1-collection-elements
	    asn1-collection:find-tagged-object

	    der-sequence? make-der-sequence <der-sequence>
	    der-sequence der-sequence-elements
	    der-sequence-of?
	    der-sequence->simple-asn1-encodable
	    
	    der-set? make-der-set <der-set>
	    der-set der-set-elements
	    der-set-of?
	    der-set:add!
	    der-set->simple-asn1-encodable
	    
	    der-numeric-string? make-der-numeric-string
	    der-numeric-string-value
	    bytevector->der-numeric-string
	    
	    der-printable-string? make-der-printable-string
	    der-printable-string-value
	    bytevector->der-printable-string

	    der-t61-string? make-der-t61-string der-t61-string-value
	    bytevector->der-t61-string

	    der-videotex-string? make-der-videotex-string
	    der-videotex-string-value
	    bytevector->der-videotex-string

	    der-ia5-string? make-der-ia5-string
	    der-ia5-string-value
	    bytevector->der-ia5-string
	    
	    der-utc-time? make-der-utc-time
	    der-utc-time-value
	    bytevector->der-utc-time

	    der-generalized-time? make-der-generalized-time
	    der-generalized-time-value
	    bytevector->der-generalized-time

	    der-graphic-string? make-der-graphic-string
	    der-graphic-string-value
	    bytevector->der-graphic-string

	    der-visible-string? make-der-visible-string
	    der-visible-string-value
	    bytevector->der-visible-string

	    der-general-string? make-der-general-string
	    der-general-string-value
	    bytevector->der-general-string

	    der-universal-string? make-der-universal-string
	    der-universal-string-value
	    bytevector->der-universal-string

	    der-bmp-string? make-der-bmp-string
	    der-bmp-string-value
	    bytevector->der-bmp-string

	    der-utf8-string? make-der-utf8-string
	    der-utf8-string-value
	    bytevector->der-utf8-string

	    der-application-specific? make-der-application-specific
	    der-application-specific-constructed?
	    der-application-specific-tag
	    der-application-specific-octets

	    der-tagged-object? make-der-tagged-object
	    der-tagged-object-tag-no
	    der-tagged-object-explicit? der-tagged-object-obj

	    der-unknown-tag? make-der-unknown-tag
	    der-unknown-tag-constructed? der-unknown-tag-number
	    der-unknown-tag-data

	    asn1-object->bytevector
	    write-asn1-object
	    describe-asn1-object

	    bytevector->asn1-object
	    read-asn1-object)
    (import (springkussen asn1 types)
	    (springkussen asn1 writer)
	    (springkussen asn1 reader)))
