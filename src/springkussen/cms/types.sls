;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cms/types.sls - Cryptographic Message Syntax
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

;; ref: https://datatracker.ietf.org/doc/html/rfc5652
#!r6rs
(library (springkussen cms types)
    (export cms-content-info? make-cms-content-info
	    cms-content-info-content-type
	    cms-content-info-content
	    asn1-object->cms-content-info

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
	    
	    cms-content-handler)
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen conditions)
	    (springkussen misc lambda)
	    (except (springkussen x509) make-x509-time make-x509-validity)
	    (springkussen x509 types))

;;;; 3. General syntex
;; ContentInfo ::= SEQUENCE {
;;   contentType ContentType,
;;   content
;;     [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }

;; ContentType ::= OBJECT IDENTIFIER
(define-record-type cms-content-info
  (parent <asn1-encodable-object>)
  (fields content-type
	  content)
  (protocol (lambda (n)
	      (lambda/typed ((content-type der-object-identifier?)
			     (content (or #f asn1-object?)))
		((n cms-content-info->asn1-object) content-type content)))))
(define (cms-content-info->asn1-object self)
  (make-der-sequence
   (filter values (list (cms-content-info-content-type self)
			(cond ((cms-content-info-content self) =>
			       (lambda (c) (make-der-tagged-object 0 #t c)))
			      (else #f))))))
(define asn1-object->cms-content-info
  (case-lambda/typed
   ((asn1-object)
    (asn1-object->cms-content-info asn1-object cms-content-handler))
   (((asn1-object der-sequence?) content-handler)
    (let ((e (asn1-collection-elements asn1-object)))
      (unless (= (length e) 2)
	(springkussen-assertion-violation 'asn1-object->cms-content-info
					  "Invalid format" asn1-object))
      (let ((ct (car e)) (c (cadr e)))
	(unless (or (not c)
		    (and (der-tagged-object? c)
			 (= (der-tagged-object-tag-no c) 0)))
	  (springkussen-assertion-violation 'asn1-object->cms-content-info
					    "Invalid format" asn1-object))
	(if c
	    (let ((content (content-handler ct (der-tagged-object-obj c))))
	      (make-cms-content-info ct content))
	    (make-cms-content-info ct c)))))))

;;;; 4.  Data Content Type
(define (data-content-handler ct content)
  (and (string=? "1.2.840.113549.1.7.1" (der-object-identifier-value ct))
       (and (der-octet-string? content))
       content))

(define/typed (der-octet-string->content-info (string der-octet-string?))
  (make-cms-content-info
   (make-der-object-identifier "1.2.840.113549.1.7.1") string))

;;;; 5 Signed-data Content Type
;;; 5.1 SignedData Type
;; SignedData ::= SEQUENCE {
;;   version CMSVersion,
;;   digestAlgorithms DigestAlgorithmIdentifiers,
;;   encapContentInfo EncapsulatedContentInfo,
;;   certificates [0] IMPLICIT CertificateSet OPTIONAL,
;;   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
;;   signerInfos SignerInfos }
;; 
;; DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
;; 
;; SignerInfos ::= SET OF SignerInfo
;;
;; RevocationInfoChoices ::= SET OF RevocationInfoChoice
;;
;; RevocationInfoChoice ::= CHOICE {
;;   crl CertificateList,
;;   other [1] IMPLICIT OtherRevocationInfoFormat }
;;
;; OtherRevocationInfoFormat ::= SEQUENCE {
;;   otherRevInfoFormat OBJECT IDENTIFIER,
;;   otherRevInfo ANY DEFINED BY otherRevInfoFormat }
(define-record-type cms-signed-data
  (parent <asn1-encodable-object>)
  (fields version
	  digest-algorithm
	  encap-content-info
	  certificates
	  crls
	  signer-infos)
  (protocol (lambda (n)
	      (lambda/typed
	       ((version der-integer?)
		(digest-algorithm algorithm-identifier?)
		(encap-content-info cms-encapsulated-content-info?)
		;; For now we only support X.509 cert
		(certificates (or #f (der-set-of? x509-certificate?)))
		;; For now we only support X.509 CRL
		(crls (or #f (der-set-of? x509-certificate-revocation-list?)))
		(signer-infos (der-set-of? cms-signer-info?)))
	       ((n cms-signed-data->asn1-object)
		version digest-algorithm encap-content-info certificates crls
		signer-infos)))))
(define (cms-signed-data->asn1-object self)
  (make-der-sequence
   (filter values (list (cms-signed-data-version self)
			(cms-signed-data-digest-algorithm self)
			(cms-signed-data-encap-content-info self)
			(cond ((cms-signed-data-certificates self) =>
			       (lambda (c) (make-der-tagged-object 0 #f c)))
			      (else #f))
			(cond ((cms-signed-data-crls self) =>
			       (lambda (c) (make-der-tagged-object 1 #f c)))
			      (else #f))
			(cms-signed-data-signer-infos self)))))

(define/typed (asn1-object->cms-signed-data (content der-sequence?))
  (springkussen-assertion-violation 'asn1-object->cms-signed-data
				    "Not supported yet"))

(define/typed (cms-signed-data->content-info (sd cms-signed-data?))
  (make-cms-content-info
   (make-der-object-identifier "1.2.840.113549.1.7.2") sd))

(define (signed-data-content-handler ct content)
  (and (string=? "1.2.840.113549.1.7.2" (der-object-identifier-value ct))
       (and (der-sequence? content))
       (asn1-object->cms-signed-data content)))


;;; 5.2 EncapsulatedContentInfo Type
;; EncapsulatedContentInfo ::= SEQUENCE {
;;   eContentType ContentType,
;;   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
(define-record-type cms-encapsulated-content-info
  (parent <asn1-encodable-object>)
  (fields e-content-type
	  e-content)
  (protocol (lambda (n)
	      (lambda/typed ((e-content-type der-object-identifier?)
			     (e-content der-octet-string?))
		((n cms-encapsulated-content-info->asn1-object)
		 e-content-type e-content)))))

(define (cms-encapsulated-content-info->asn1-object self)
  (der-sequence
   (cms-encapsulated-content-info-e-content-type self)
   (make-der-tagged-object 0 #t 
			   (cms-encapsulated-content-info-e-content self))))
;;; 5.3 SignerInfo Type
;; SignerInfo ::= SEQUENCE {
;;   version CMSVersion,
;;   sid SignerIdentifier,
;;   digestAlgorithm DigestAlgorithmIdentifier,
;;   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
;;   signatureAlgorithm SignatureAlgorithmIdentifier,
;;   signature SignatureValue,
;;   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
;;
;; SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
;;
;; UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
;; 
;; SignatureValue ::= OCTET STRING
(define-record-type cms-signer-info
  (parent <asn1-encodable-object>)
  (fields version
	  sid
	  digest-algorithm
	  signed-attrs
	  signature-algorithm
	  signature
	  unsigned-attrs)
  (protocol (lambda (n)
	      (lambda/typed ((version der-integer?)
			     (sid cms-signer-identifier?)
			     (digest-algorithm algorithm-identifier?)
			     (signed-attrs (or #f (der-set-of? cms-attribute?)))
			     (signature-algorithm algorithm-identifier?)
			     (sigature der-octet-string?)
			     (unsigned-attrs
			      (or #f (der-set-of? cms-attribute?))))
	       ((n cms-signer-info->asn1-object)
		version sid digest-algorithm signed-attrs signature-algorithm
		sigature unsigned-attrs)))))

(define (cms-signer-info->asn1-object self)
  (make-der-sequence
   (filter values (list
		   (cms-signer-info-version self)
		   (cms-signer-info-sid self)
		   (cms-signer-info-digest-algorithm self)
		   (cond ((cms-signer-info-signed-attrs self) =>
			  (lambda (c) (make-der-tagged-object 0 #f c)))
			 (else #f))
		   (cms-signer-info-signature-algorithm self)
		   (cms-signer-info-signature self)
		   (cond ((cms-signer-info-unsigned-attrs self) =>
			  (lambda (c) (make-der-tagged-object 0 #f c)))
			 (else #f))))))

;; SignerIdentifier ::= CHOICE {
;;   issuerAndSerialNumber IssuerAndSerialNumber,
;;   subjectKeyIdentifier [0] SubjectKeyIdentifier }
;;
;; SubjectKeyIdentifier ::= OCTET STRING
;; Base type for above choice (there are quite a lot of the same structures)
(define-record-type cms-identifier-choice
  (parent <asn1-encodable-object>)
  (fields issuer-and-serial-number
	  subject-key-identifier)
  (protocol (lambda (n)
	      (case-lambda/typed
	       (((issuer-and-serial-number
		  (or #f cms-issuer-and-serial-number?))
		 (subject-key-identifier (or #f der-octet-string?)))
		(unless (or issuer-and-serial-number subject-key-identifier)
		  (springkussen-assertion-violation 'make-identifier-choice
		    "One of the fields are required"))
		((n cms-identifier-choice->asn1-object)
		 issuer-and-serial-number subject-key-identifier))
	       (((converter procedure?)
		 (issuer-and-serial-number
		  (or #f cms-issuer-and-serial-number?))
		 (subject-key-identifier (or #f der-octet-string?)))
		(unless (or issuer-and-serial-number subject-key-identifier)
		  (springkussen-assertion-violation 'make-identifier-choice
		    "One of the fields are required"))
		((n converter)
		 issuer-and-serial-number subject-key-identifier))))))
(define (cms-identifier-choice->asn1-object self)
  (cond ((cms-identifier-choice-issuer-and-serial-number self))
	((cms-identifier-choice-subject-key-identifier self) =>
	 (lambda (c) (make-der-tagged-object 0 #f c)))
	(else (springkussen-assertion-violation
	       'cms-identifier-choice->asn1-object "Unknown object" self))))
(define-record-type cms-signer-identifier
  (parent cms-identifier-choice)
  (protocol (lambda (n) (lambda (i s) ((n i s))))))

;; Attribute ::= SEQUENCE {
;;   attrType OBJECT IDENTIFIER,
;;   attrValues SET OF AttributeValue }
;;
;; AttributeValue ::= ANY
(define-record-type cms-attribute
  (parent <asn1-encodable-object>)
  (fields attr-type
	  attr-value)
  (protocol (lambda (n)
	      (lambda/typed ((attr-type der-object-identifier?)
			     (attr-value asn1-object?))
		((n simple-asn1-encodable-object->der-sequence)
		 attr-type attr-value)))))

;;;;  6. Enveloped-Data Content Type
;;; 6.1. EnvelopedData Type
;; EnvelopedData ::= SEQUENCE {
;;   version CMSVersion,
;;   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
;;   recipientInfos RecipientInfos,
;;   encryptedContentInfo EncryptedContentInfo,
;;   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
;;
;; RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
;; 
;; UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
(define-record-type cms-enveloped-data
  (parent <asn1-encodable-object>)
  (fields version
	  originator-info
	  recipient-infos
	  encrypted-content-info
	  unprotected-attrs)
  (protocol (lambda (n)
	      (lambda/typed ((version der-integer?)
			     (originator-info (or #f cms-originator-info?))
			     (recipient-infos (der-set-of? cms-recipient-info?))
			     (encrypted-content-info
			      cms-encrypted-content-info?)
			     (unprotected-attrs 
			      (or #f (der-set-of? cms-attribute?))))
		((n enveloped-data->asn1-object)
		 version originator-info recipient-infos encrypted-content-info
		 unprotected-attrs)))))
(define (enveloped-data->asn1-object self)
  (make-der-sequence
   (filter values
	   (list (cms-enveloped-data-version self)
		 (cond ((cms-enveloped-data-originator-info self) =>
			(lambda (c) (make-der-tagged-object 0 #f c)))
		       (else #f))
		 (cms-enveloped-data-recipient-infos self)
		 (cms-enveloped-data-encrypted-content-info self)
		 (cond ((cms-enveloped-data-unprotected-attrs self) =>
			(lambda (c) (make-der-tagged-object 0 #f c)))
		       (else #f))))))

(define/typed (cms-enveloped-data->content-info (ed cms-enveloped-data?))
  (make-cms-content-info
   (make-der-object-identifier "1.2.840.113549.1.7.3") ed))

;; OriginatorInfo ::= SEQUENCE {
;;   certs [0] IMPLICIT CertificateSet OPTIONAL,
;;   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }
(define-record-type cms-originator-info
  (parent <asn1-encodable-object>)
  (fields certs crls)
  (protocol (lambda (n)
	      (lambda/typed ((certs (der-set-of? x509-certificate?))
			     (crls
			      (der-set-of? x509-certificate-revocation-list?)))
	       ((n cms-originator-info->asn1-object) certs crls)))))
(define (cms-originator-info->asn1-object self)
  (make-der-sequence
   (filter values
	   (list (cond ((cms-originator-info-certs self) =>
			(lambda (c) (make-der-tagged-object 0 #f c)))
		       (else #f))
		 (cond ((cms-originator-info-crls self) =>
			(lambda (c) (make-der-tagged-object 1 #f c)))
		       (else #f))))))


;; EncryptedContentInfo ::= SEQUENCE {
;;   contentType ContentType,
;;   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
;;   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
;;
;; EncryptedContent ::= OCTET STRING
(define-record-type cms-encrypted-content-info
  (parent <asn1-encodable-object>)
  (fields content-type
	  content-encryption-algorithm
	  encrypted-content)
  (protocol (lambda (n)
	      (lambda/typed ((content-type der-object-identifier?)
			     (content-encryption-algorithm
			      algorithm-identifier?)
			     (encrypted-content (or #f der-octet-string?)))
	       ((n cms-encrypted-content-info->asn1-object)
		content-type content-encryption-algorithm encrypted-content)))))
(define (cms-encrypted-content-info->asn1-object self)
  (make-der-sequence
   (filter values
	   (list (cms-encrypted-content-info-content-type self)
		 (cms-encrypted-content-info-content-encryption-algorithm self)
		 (cond ((cms-encrypted-content-info-encrypted-content self) =>
			(lambda (c) (make-der-tagged-object 0 #f c)))
		       (else #f))))))

(define/typed (asn1-object->cms-encrypted-content-info
	       (asn1-object der-sequence?))
  (let ((e (asn1-collection-elements asn1-object)))
    (when (< (length e) 2)
      (springkussen-assertion-violation 'asn1-object->cms-encrypted-content-info
					"Invalid format"))
    (let ((content (asn1-collection:find-tagged-object asn1-object 0)))
      (make-cms-encrypted-content-info
       (car e)
       (asn1-object->algorithm-identifier (cadr e))
       (and content (der-tagged-object-obj content))))))

;;; 6.2. RecipientInfo Type
;; RecipientInfo ::= CHOICE {
;;   ktri KeyTransRecipientInfo,
;;   kari [1] KeyAgreeRecipientInfo,
;;   kekri [2] KEKRecipientInfo,
;;   pwri [3] PasswordRecipientinfo,
;;   ori [4] OtherRecipientInfo }
(define-record-type cms-recipient-info
  (parent <asn1-encodable-object>)
  (fields ktri
	  kari
	  kekri
	  pwri
	  ori)
  (protocol (lambda (n)
	      (lambda/typed ((ktri (or #f cms-key-trans-recipient-info?))
			     (kari (or #f cms-key-agree-recipient-info?))
			     (kekri (or #f cms-kek-recipient-info?))
			     (pwri (or #f cms-password-recipient-info?))
			     (ori (or #f cms-other-recipient-info?)))
		(unless (or ktri kari kekri pwri ori)
		  (springkussen-assertion-violation 'make-cms-recipient-info
		    "One of the fields are required"))
		((n cms-recpient-info->asn1-object)
		 ktri kari kekri pwri ori)))))
(define (cms-recpient-info->asn1-object self)
  (cond ((cms-recipient-info-ktri self))
	((cms-recipient-info-kari self) =>
	 (lambda (c) (make-der-tagged-object 1 #f c)))
	((cms-recipient-info-kekri self) =>
	 (lambda (c) (make-der-tagged-object 2 #f c)))
	((cms-recipient-info-pwri self) =>
	 (lambda (c) (make-der-tagged-object 3 #f c)))
	((cms-recipient-info-ori self) =>
	 (lambda (c) (make-der-tagged-object 4 #f c)))
	(else (springkussen-assertion-violation 'cms-recipient-info->asn1-object
						"Unknown object" self))))

;;; 6.2.1. KeyTransRecipientInfo Type
;; KeyTransRecipientInfo ::= SEQUENCE {
;;   version CMSVersion,  -- always set to 0 or 2
;;   rid RecipientIdentifier,
;;   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
;;   encryptedKey EncryptedKey }
;;
;; EncryptedKey ::= OCTET STRING
(define-record-type cms-key-trans-recipient-info
  (parent <asn1-encodable-object>)
  (fields version rid key-encryption-algorithm encrypted-key)
  (protocol (lambda (n)
	      (define (version0or2? i)
		(and (der-integer? i)
		     (memv (der-integer-value i) '(0 2))))
	      (lambda/typed ((version version0or2?)
			     (rid cms-recipient-identifier?)
			     (key-encryption-algorithm algorithm-identifier?)
			     (encrypted-key der-octet-string?))
		((n simple-asn1-encodable-object->der-sequence)
		 version rid key-encryption-algorithm encrypted-key)))))

;; RecipientIdentifier ::= CHOICE {
;;   issuerAndSerialNumber IssuerAndSerialNumber,
;;   subjectKeyIdentifier [0] SubjectKeyIdentifier }
(define-record-type cms-recipient-identifier
  (parent cms-identifier-choice)
  (protocol (lambda (n) (lambda (i s) ((n i s))))))


;;; 6.2.2. KeyAgreeRecipientInfo Type
;; KeyAgreeRecipientInfo ::= SEQUENCE {
;;   version CMSVersion,  -- always set to 3
;;   originator [0] EXPLICIT OriginatorIdentifierOrKey,
;;   ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
;;   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
;;   recipientEncryptedKeys RecipientEncryptedKeys }
;;
;; RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
(define-record-type cms-key-agree-recipient-info
  (parent <asn1-encodable-object>)
  (fields version
	  originator
	  ukm
	  key-encryption-algorithm
	  recipient-encrypted-keys)
  (protocol (lambda (n)
	      (define (version3? v)
		(and (der-integer? v)
		     (= (der-integer-value v) 3)))
	      (lambda/typed ((version version3?)
			     (originator cms-originator-identifier-or-key?)
			     (ukm (or #f der-octet-string?))
			     (key-encryption-algorithm algorithm-identifier?)
			     (recipient-encrypted-keys
			      (der-sequence-of? cms-recipient-encrypted-key?)))
		((n cms-key-agree-recipient-info->asn1-object)
		 version originator ukm key-encryption-algorithm
		 recipient-encrypted-keys)))))
(define (cms-key-agree-recipient-info->asn1-object self)
  (make-der-sequence
   (filter
    values
    (list (cms-key-agree-recipient-info-version self)
	  (make-der-tagged-object 0 #t
	   (cms-key-agree-recipient-info-originator self))
	  (cond ((cms-key-agree-recipient-info-ukm self) =>
		 (lambda (c) (make-der-tagged-object 1 #t c)))
		(else #f))
	  (cms-key-agree-recipient-info-key-encryption-algorithm self)
	  (cms-key-agree-recipient-info-recipient-encrypted-keys self)))))

;; OriginatorIdentifierOrKey ::= CHOICE {
;;   issuerAndSerialNumber IssuerAndSerialNumber,
;;   subjectKeyIdentifier [0] SubjectKeyIdentifier,
;;   originatorKey [1] OriginatorPublicKey }
(define-record-type cms-originator-identifier-or-key
  (parent cms-identifier-choice)
  (fields originator-key)
  (protocol (lambda (n)
	      (lambda/typed ((issuer-and-serial-number
			      (or #f cms-issuer-and-serial-number?))
			     (subject-key-identifier (or #f der-octet-string?))
			     (originator-key
			      (or #f cms-originator-public-key?)))
	       (unless (or issuer-and-serial-number subject-key-identifier
			   originator-key)
		 (springkussen-assertion-violation
		  'make-cms-originator-identifier-or-key
		  "One of the fields are required"))
	       ((n cms-originator-identifier-or-key->asn1-object
		   issuer-and-serial-number subject-key-identifier)
		originator-key)))))
(define (cms-originator-identifier-or-key->asn1-object self)
  (cond ((cms-originator-identifier-or-key-originator-key self) =>
	 (lambda (c) (make-der-tagged-object 1 #f c)))
	(else (cms-identifier-choice->asn1-object self))))

;; OriginatorPublicKey ::= SEQUENCE {
;;   algorithm AlgorithmIdentifier,
;;   publicKey BIT STRING }
(define-record-type cms-originator-public-key
  (parent <asn1-encodable-object>)
  (fields algorithm public-key)
  (protocol (lambda (n)
	      (lambda/typed ((algorithm algorithm-identifier?)
			     (public-key der-bit-string?))
		((n simple-asn1-encodable-object->der-sequence) 
		 algorithm public-key)))))
(define/typed (cms-originator-public-key->public-key
	       (originator-public-key cms-originator-public-key?))
  ;; Lazy way...
  (subject-public-key-info->public-key
   (make-subject-public-key-info 
    (cms-originator-public-key-algorithm originator-public-key)
    (cms-originator-public-key-public-key originator-public-key))))

;; RecipientEncryptedKey ::= SEQUENCE {
;;   rid KeyAgreeRecipientIdentifier,
;;   encryptedKey EncryptedKey }
(define-record-type cms-recipient-encrypted-key
  (parent <asn1-encodable-object>)
  (fields rid encrypted-key)
  (protocol (lambda (n)
	      (lambda/typed ((rid cms-key-agree-recipient-identifier?)
			     (encrypted-key der-octet-string?))
		((n simple-asn1-encodable-object->der-sequence) 
		 rid encrypted-key)))))

;; KeyAgreeRecipientIdentifier ::= CHOICE {
;;   issuerAndSerialNumber IssuerAndSerialNumber,
;;   rKeyId [0] IMPLICIT RecipientKeyIdentifier }
(define-record-type cms-key-agree-recipient-identifier
  (parent <asn1-encodable-object>)
  (fields issuer-and-serial-number r-key-id)
  (protocol (lambda (n)
	      (lambda/typed ((issuer-and-serial-number
			      (or #f cms-issuer-and-serial-number?))
			     (r-key-id (or #f cms-recipient-key-identifier?)))
	        (unless (or issuer-and-serial-number r-key-id)
		  (springkussen-assertion-violation
		   'make-cms-key-agree-recipient-identifier
		   "One of the fields are required"))
		((n cms-key-agree-recipient-identifier->asn1-object)
		 issuer-and-serial-number r-key-id)))))
(define (cms-key-agree-recipient-identifier->asn1-object self)
  (cond ((cms-key-agree-recipient-identifier-issuer-and-serial-number self))
	((cms-key-agree-recipient-identifier-r-key-id self) =>
	 (lambda (c) (make-der-tagged-object 0 #f c)))
	(else (springkussen-assertion-violation
	       'cms-key-agree-recipient-identifier->asn1-object
	       "Unknown object" self))))

;; RecipientKeyIdentifier ::= SEQUENCE {
;;   subjectKeyIdentifier SubjectKeyIdentifier,
;;   date GeneralizedTime OPTIONAL,
;;   other OtherKeyAttribute OPTIONAL }
(define-record-type cms-recipient-key-identifier
  (parent <asn1-encodable-object>)
  (fields subject-key-identifier
	  date
	  other)
  (protocol (lambda (n)
	      (lambda/typed ((subject-key-identifier der-octet-string?)
			     (date (or #f der-generalized-time?))
			     (other (or #f cms-other-key-attribute?)))
	       ((n simple-asn1-encodable-object->der-sequence)
		subject-key-identifier date other)))))

;;; 6.2.3 KEKRecipientInfo Type
;; KEKRecipientInfo ::= SEQUENCE {
;;   version CMSVersion,  -- always set to 4
;;   kekid KEKIdentifier,
;;   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
;;   encryptedKey EncryptedKey }
(define-record-type cms-kek-recipient-info
  (parent <asn1-encodable-object>)
  (fields version
	  kekid
	  key-encryption-algorithm
	  encrypted-key)
  (protocol (lambda (n)
	      (define (version4? v)
		(and (der-integer? v)
		     (= (der-integer-value v) 4)))
	      (lambda/typed ((version version4?)
			     (kekid cms-kek-identifier?)
			     (key-encryption-algorithm algorithm-identifier?)
			     (encrypted-key der-octet-string?))
	       ((n simple-asn1-encodable-object->der-sequence)
		version kekid key-encryption-algorithm encrypted-key)))))
;; KEKIdentifier ::= SEQUENCE {
;;   keyIdentifier OCTET STRING,
;;   date GeneralizedTime OPTIONAL,
;;   other OtherKeyAttribute OPTIONAL }
(define-record-type cms-kek-identifier
  (parent <asn1-encodable-object>)
  (fields kek-identifier date other)
  (protocol (lambda (n)
	      (lambda/typed ((kek-identifier der-octet-string?)
			     (date der-generalized-time?)
			     (other (or #f cms-other-key-attribute?)))
	       ((n simple-asn1-encodable-object->der-sequence)
		kek-identifier date other)))))

;;; 6.2.4. PasswordRecipient
;; PasswordRecipientInfo ::= SEQUENCE {
;;   version CMSVersion,   -- Always set to 0
;;   keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
;;                                OPTIONAL,
;;   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
;;   encryptedKey EncryptedKey }
(define-record-type cms-password-recipient-info
  (parent <asn1-encodable-object>)
  (fields version
	  key-derivation-algorithm
	  key-encryption-algorithm
	  encrypted-key)
  (protocol (lambda (n)
	      (define (version0? v)
		(and (der-integer? v)
		     (= (der-integer-value v) 0)))
	      (lambda/typed ((version version0?)
			     (key-derivation-algorithm
			      (or #f algorithm-identifier?))
			     (key-encryption-algorithm algorithm-identifier?)
			     (encrypted-key der-octet-string?))
	        ((n cms-password-recipient->asn1-object)
		 version key-derivation-algorithm key-encryption-algorithm
		 encrypted-key)))))

(define (cms-password-recipient->asn1-object self)
  (make-der-sequence
   (filter values
    (list (cms-password-recipient-info-version self)
	  (cond ((cms-password-recipient-info-key-derivation-algorithm self) =>
		 (lambda (c) (make-der-tagged-object 0 #f c)))
		(else #f))
	  (cms-password-recipient-info-key-encryption-algorithm self)
	  (cms-password-recipient-info-encrypted-key self)))))

;;; 6.2.5 OtherRecipientInfo Type
;; OtherRecipientInfo ::= SEQUENCE {
;;   oriType OBJECT IDENTIFIER,
;;   oriValue ANY DEFINED BY oriType }
(define-record-type cms-other-recipient-info
  (parent <asn1-encodable-object>)
  (fields ori-type ori-value)
  (protocol (lambda (n)
	      (lambda/typed ((ori-type der-object-identifier?)
			     (ori-value asn1-object?))
	        ((n simple-asn1-encodable-object->der-sequence) 
		 ori-type ori-value)))))

;;;; 7. Digested-data Content Type
;; DigestedData ::= SEQUENCE {
;;   version CMSVersion,
;;   digestAlgorithm DigestAlgorithmIdentifier,
;;   encapContentInfo EncapsulatedContentInfo,
;;   digest Digest }
;;
;; Digest ::= OCTET STRING
(define-record-type cms-digested-data
  (parent <asn1-encodable-object>)
  (fields version digest-algorithm encap-content-info digest)
  (protocol (lambda (n)
	      (lambda/typed ((version der-integer?)
			     (digest-algorithm algorithm-identifier?)
			     (encap-content-info cms-encapsulated-content-info?)
			     (digest der-octet-string?))
	       ((n simple-asn1-encodable-object->der-sequence)
		version digest-algorithm encap-content-info digest)))))
(define/typed (cms-digested-data->content-info (dd cms-digested-data?))
  (make-cms-content-info
   (make-der-object-identifier "1.2.840.113549.1.7.5") dd))

;;;; 8. Encrypted-data Content Type
;; EncryptedData ::= SEQUENCE {
;;   version CMSVersion,
;;   encryptedContentInfo EncryptedContentInfo,
;;   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
(define-record-type cms-encrypted-data
  (parent <asn1-encodable-object>)
  (fields version encrypted-content-info unprotected-attrs)
  (protocol (lambda (n)
	      (define (check-version version attrs)
		(or (and attrs (= (der-integer-value version) 2))
		    (and (not attrs) (= (der-integer-value version) 0))))
	      (lambda/typed ((version der-integer?)
			     (encrypted-content-info
			      cms-encrypted-content-info?)
			     (unprotected-attrs
			      (or #f (der-set-of? cms-attribute?))))
	        (unless (check-version version unprotected-attrs)
		  (springkussen-assertion-violation 'make-cms-encrypted-data
		    "Version must be 0 if attrs is not present, or 2 if attrs is present"))
	        ((n cms-encrypted-data->asn1-object)
		 version encrypted-content-info unprotected-attrs)))))
(define (cms-encrypted-data->asn1-object self)
  (make-der-sequence
   (filter values
	   (list (cms-encrypted-data-version self)
		 (cms-encrypted-data-encrypted-content-info self)
		 (cond ((cms-encrypted-data-unprotected-attrs self) =>
			(lambda (c) (make-der-tagged-object 0 #f c)))
		       (else #f))))))
(define/typed (asn1-object->cms-encrypted-data (asn1-object der-sequence?))
  (let ((e (asn1-collection-elements asn1-object)))
    (when (< (length e) 2)
      (springkussen-assertion-violation 'asn1-object->cms-encrypted-data
					"Invalid format" asn1-object))
    (let ((attrs (asn1-collection:find-tagged-object asn1-object 0)))
      (make-cms-encrypted-data
       (car e)
       (asn1-object->cms-encrypted-content-info (cadr e))
       (and attrs (der-tagged-object-obj attrs))))))

(define/typed (cms-encrypted-data->content-info (ed cms-encrypted-data?))
  (make-cms-content-info
   (make-der-object-identifier "1.2.840.113549.1.7.6") ed))

(define (encrypted-data-content-handler ct content)
  (and (string=? "1.2.840.113549.1.7.6" (der-object-identifier-value ct))
       (and (der-sequence? content))
       (asn1-object->cms-encrypted-data content)))

;;;; 9.    Authenticated-data Content Type
;;;  9.1.  AuthenticatedData Type
;; AuthenticatedData ::= SEQUENCE {
;;   version CMSVersion,
;;   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
;;   recipientInfos RecipientInfos,
;;   macAlgorithm MessageAuthenticationCodeAlgorithm,
;;   digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
;;   encapContentInfo EncapsulatedContentInfo,
;;   authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
;;   mac MessageAuthenticationCode,
;;   unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
;;
;; AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
;;
;; UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
;;
;; MessageAuthenticationCode ::= OCTET STRING
(define-record-type cms-authenticated-data
  (parent <asn1-encodable-object>)
  (fields version
	  originator-info
	  recipient-infos
	  mac-algorithm
	  digest-algorithm
	  encap-content-info
	  auth-attrs
	  mac
	  unauth-attrs)
  (protocol (lambda (n)
	      (lambda/typed ((version der-integer?)
			     (originator-info (or #f cms-originator-info?))
			     (recipient-infos (der-set-of? cms-recipient-info?))
			     (mac-algorithm algorithm-identifier?)
			     (digest-algorithm (or #f algorithm-identifier?))
			     (encap-content-info cms-encapsulated-content-info?)
			     (auth-attrs (or #f (der-set-of? cms-attribute?)))
			     (mac der-octet-string?)
			     (unauth-attrs
			      (or #f (der-set-of? cms-attribute?))))
	       ((n cms-authenticated-data->asn1-object)
		version originator-info recipient-infos
		mac-algorithm digest-algorithm encap-content-info
		auth-attrs mac unauth-attrs)))))
(define (cms-authenticated-data->asn1-object self)
  (make-der-sequence
   (filter values
	   (list (cms-authenticated-data-version self)
		 (cond ((cms-authenticated-data-originator-info self) =>
			(lambda (c) (make-der-tagged-object 0 #f c)))
		       (else #f))
		 (cms-authenticated-data-recipient-infos self)
		 (cms-authenticated-data-mac-algorithm self)
		 (cond ((cms-authenticated-data-digest-algorithm self) =>
			(lambda (c) (make-der-tagged-object 1 #f c)))
		       (else #f))
		 (cms-authenticated-data-encap-content-info self)
		 (cond ((cms-authenticated-data-auth-attrs self) =>
			(lambda (c) (make-der-tagged-object 2 #f c)))
		       (else #f))
		 (cms-authenticated-data-mac self)
		 (cond ((cms-authenticated-data-unauth-attrs self) =>
			(lambda (c) (make-der-tagged-object 3 #f c)))
		       (else #f))))))

(define/typed (cms-authenticated-data->content-info (ed cms-encrypted-data?))
  (make-cms-content-info
   (make-der-object-identifier "1.2.840.113549.1.9.16.1.2") ed))

;;;; 10.    Useful Types
;;;  10.2   Other Useful Types

;;   10.2.4 IssuerAndSerialNumber
;; IssuerAndSerialNumber ::= SEQUENCE {
;;   issuer Name,
;;   serialNumber CertificateSerialNumber }
;;
;; CertificateSerialNumber ::= INTEGER
(define-record-type cms-issuer-and-serial-number
  (parent <asn1-encodable-object>)
  (fields name serial-number)
  (protocol (lambda (n)
	      (lambda/typed ((name x509-name?)
			     (serial-number der-integer?))
		((n simple-asn1-encodable-object->der-sequence) 
		 name serial-number)))))

;;   10.2.7 OtherKeyAttribute
;; OtherKeyAttribute ::= SEQUENCE {
;;   keyAttrId OBJECT IDENTIFIER,
;;   keyAttr ANY DEFINED BY keyAttrId OPTIONAL }
(define-record-type cms-other-key-attribute
  (parent <asn1-encodable-object>)
  (fields key-attr-id key-attr)
  (protocol (lambda (n)
	      (lambda/typed ((key-attr-id der-object-identifier?)
			     (key-attr (or #f asn1-object?)))
	       ((n simple-asn1-encodable-object->der-sequence) 
		key-attr-id key-attr)))))

(define/typed (cms-content-handler (ct der-object-identifier?)
				   (content asn1-object?))
  (or (data-content-handler ct content)
      (signed-data-content-handler ct content)
      (encrypted-data-content-handler ct content)))
  
)
