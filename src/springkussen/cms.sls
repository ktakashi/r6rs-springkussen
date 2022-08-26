;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cms.sls - Cryptographic Message Syntax
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
(library (springkussen cms)
    (export cms-content-info? make-cms-content-info
	    cms-content-info-content-type
	    cms-content-info-content
	    asn1-object->cms-content-info

	    ;; 4 Data Content Type
	    der-octet-string->content-info
	    
	    ;; 5 Signed-data Content Type
	    cms-signed-data? make-cms-signed-data
	    cms-signed-data-version
	    cms-signed-data-digest-algorithm
	    cms-signed-data-encap-content-info
	    cms-signed-data-certificates
	    cms-signed-data-crls
	    cms-signed-data-signer-infos
	    cms-signed-data->content-info

	    cms-encapsulated-content-info? make-cms-encapsulated-content-info
	    cms-encapsulated-content-info-e-content-type
	    cms-encapsulated-content-info-e-content

	    cms-signer-info? make-cms-signer-info
	    cms-signer-info-version
	    cms-signer-info-sid
	    cms-signer-info-digest-algorithm
	    cms-signer-info-signed-attrs
	    cms-signer-info-signature-algorithm
	    cms-signer-info-signature
	    cms-signer-info-unsigned-attrs

	    cms-identifier-choice-issuer-and-serial-number
	    cms-identifier-choice-subject-key-identifier
	    cms-signer-identifier? make-cms-signer-identifier

	    cms-attribute? make-cms-attribute
	    cms-attribute-attr-type
	    cms-attribute-attr-value

	    ;; 6. Enveloped-Data Content Type
	    cms-enveloped-data? make-cms-enveloped-data
	    cms-enveloped-data-version
	    cms-enveloped-data-originator-info
	    cms-enveloped-data-recipient-infos
	    cms-enveloped-data-encrypted-content-info
	    cms-enveloped-data-unprotected-attrs
	    cms-enveloped-data->content-info

	    cms-originator-info? make-cms-originator-info
	    cms-originator-info-certs
	    cms-originator-info-crls
	    
	    cms-encrypted-content-info? make-cms-encrypted-content-info
	    cms-encrypted-content-info-content-type
	    cms-encrypted-content-info-content-encryption-algorithm
	    cms-encrypted-content-info-encrypted-content

	    cms-recipient-info? make-cms-recipient-info
	    
	    cms-key-trans-recipient-info? make-cms-key-trans-recipient-info
	    cms-key-trans-recipient-info-version
	    cms-key-trans-recipient-info-key-encryption-algorithm
	    cms-key-trans-recipient-info-encrypted-key

	    cms-recipient-identifier? make-cms-recipient-identifier

	    cms-key-agree-recipient-info? make-cms-key-agree-recipient-info
	    cms-key-agree-recipient-info-version
	    cms-key-agree-recipient-info-originator
	    cms-key-agree-recipient-info-ukm
	    cms-key-agree-recipient-info-key-encryption-algorithm
	    cms-key-agree-recipient-info-recipient-encrypted-keys

	    cms-originator-identifier-or-key?
	    make-cms-originator-identifier-or-key
	    cms-originator-identifier-or-key-originator-key

	    cms-originator-public-key? make-cms-originator-public-key
	    cms-originator-public-key->public-key
	    cms-originator-public-key-algorithm
	    cms-originator-public-key-public-key

	    cms-recipient-encrypted-key? make-cms-recipient-encrypted-key
	    cms-recipient-encrypted-key-rid
	    cms-recipient-encrypted-key-encrypted-key

	    cms-key-agree-recipient-identifier?
	    make-cms-key-agree-recipient-identifier
	    cms-key-agree-recipient-identifier-issuer-and-serial-number
	    cms-key-agree-recipient-identifier-r-key-id

	    cms-recipient-key-identifier? make-cms-recipient-key-identifier
	    cms-recipient-key-identifier-subject-key-identifier
	    cms-recipient-key-identifier-date
	    cms-recipient-key-identifier-other

	    cms-kek-recipient-info? make-cms-kek-recipient-info
	    cms-kek-recipient-info-version
	    cms-kek-recipient-info-kekid
	    cms-kek-recipient-info-key-encryption-algorithm
	    cms-kek-recipient-info-encrypted-key

	    cms-kek-identifier? make-cms-kek-identifier
	    cms-kek-identifier-kek-identifier
	    cms-kek-identifier-date
	    cms-kek-identifier-other

	    cms-password-recipient-info? make-cms-password-recipient-info
	    cms-password-recipient-info-version
	    cms-password-recipient-info-key-derivation-algorithm
	    cms-password-recipient-info-key-encryption-algorithm
	    cms-password-recipient-info-encrypted-key

	    cms-other-recipient-info? make-cms-other-recipient-info
	    cms-other-recipient-info-ori-type
	    cms-other-recipient-info-ori-value

	    ;; 7. Digested-data Content Type
	    cms-digested-data? make-cms-digested-data
	    cms-digested-data-version
	    cms-digested-data-digest-algorithm
	    cms-digested-data-encap-content-info
	    cms-digested-data-digest
	    cms-digested-data->content-info

	    ;; 8. Encrypted-data Content Type
	    cms-encrypted-data? make-cms-encrypted-data
	    cms-encrypted-data-version
	    cms-encrypted-data-encrypted-content-info
	    cms-encrypted-data-unprotected-attrs
	    cms-encrypted-data->content-info

	    ;; 9. Authenticated-data Content Type
	    cms-authenticated-data? make-cms-authenticated-data
	    cms-authenticated-data-version
	    cms-authenticated-data-originator-info
	    cms-authenticated-data-recipient-infos
	    cms-authenticated-data-mac-algorithm
	    cms-authenticated-data-digest-algorithm
	    cms-authenticated-data-encap-content-info
	    cms-authenticated-data-auth-attrs
	    cms-authenticated-data-mac
	    cms-authenticated-data-unauth-attrs
	    cms-authenticated-data->content-info
	    
	    ;; 10. Useful types
	    cms-issuer-and-serial-number? make-cms-issuer-and-serial-number
	    cms-issuer-and-serial-number-name
	    cms-issuer-and-serial-number-serial-number

	    cms-other-key-attribute? make-cms-other-key-attribute
	    cms-other-key-attribute-key-attr-id
	    cms-other-key-attribute-key-attr
	    
	    cms-content-handler

	    ;; operations
	    cms-data-content-info?
	    cms-data-content-info:content

	    cms-encrypted-data-content-info?
	    cms-enctypted-data-content-info:encryption-algorithm
	    cms-enctypted-data-content-info:decrypt-content
	    
	    cms-encrypted-data:encryption-algorithm
	    cms-encrypted-data:decrypt-content

	    ;; Asymmetric Key Package
	    cms-one-asymmetric-key? make-cms-one-asymmetric-key
	    cms-one-asymmetric-key-version
	    cms-one-asymmetric-key-private-key-algorithm
	    cms-one-asymmetric-key-private-key
	    cms-one-asymmetric-key-attributes
	    cms-one-asymmetric-key-public-key
	    asn1-object->cms-one-asymmetric-key
	    bytevector->cms-one-asymmetric-key
	    cms-one-asymmetric-key->private-key
	    private-key->cms-one-asymmetric-key
	    
	    make-cms-private-key-info
	    cms-private-key-info?
	    asn1-object->cms-private-key-info
	    bytevector->cms-private-key-info
	    cms-private-key-info->private-key
	    private-key->cms-private-key-info

	    cms-encrypted-private-key-info? make-cms-encrypted-private-key-info
	    cms-encrypted-private-key-info-encryption-algorithm
	    cms-encrypted-private-key-info-encrypted-data
	    asn1-object->cms-encrypted-private-key-info)
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen cms types)
	    (springkussen cms akp)
	    (springkussen cipher symmetric)
	    (springkussen misc lambda))

(define (cms-data-content-info? obj)
  (and (cms-content-info? obj)
       (der-octet-string? (cms-content-info-content obj))))
(define/typed (cms-data-content-info:content
	       (info cms-data-content-info?))
  (cms-content-info-content info))

  
(define (cms-encrypted-data-content-info? obj)
  (and (cms-content-info? obj)
       (cms-encrypted-data? (cms-content-info-content obj))))

(define/typed (cms-enctypted-data-content-info:encryption-algorithm
	       (info cms-encrypted-data-content-info?))
  (cms-encrypted-data:encryption-algorithm (cms-content-info-content info)))

(define cms-enctypted-data-content-info:decrypt-content
  (case-lambda/typed
   (((info cms-encrypted-data-content-info?) cipher key)
    (cms-encrypted-data:decrypt-content (cms-content-info-content info)
					cipher key #f))
   (((info cms-encrypted-data-content-info?) cipher key parameter)
    (cms-encrypted-data:decrypt-content (cms-content-info-content info)
					cipher key parameter))))

;; Returns algorithm identifier itself
(define/typed (cms-encrypted-data:encryption-algorithm (ed cms-encrypted-data?))
  (cms-encrypted-content-info-content-encryption-algorithm
   (cms-encrypted-data-encrypted-content-info ed)))

;; Hope no one uses RSA to encrypt...
(define cms-encrypted-data:decrypt-content
  (case-lambda/typed
   (((ed cms-encrypted-data?) (cipher symmetric-cipher?) (key symmetric-key?))
    (cms-encrypted-data:decrypt-content ed cipher key #f))
   (((ed cms-encrypted-data?)
     (cipher symmetric-cipher?)
     (key symmetric-key?)
     (parameter (or #f cipher-parameter?)))
    (let ((c (cms-encrypted-content-info-encrypted-content
	      (cms-encrypted-data-encrypted-content-info ed))))
      (and c
	   (symmetric-cipher:decrypt-bytevector cipher key parameter
						(der-octet-string-value c)))))))

)
