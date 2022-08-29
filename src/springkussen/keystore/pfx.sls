;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/keystore/pfx.sls - PFX PDU
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

;; ref: https://datatracker.ietf.org/doc/html/rfc7292
#!r6rs
(library (springkussen keystore pfx)
    (export pkcs12-keystore? pkcs12-keystore-builder
	    read-pkcs12-keystore
	    bytevector->pkcs12-keystore
	    write-pkcs12-keystore
	    pkcs12-keystore->bytevector

	    pkcs12-entry-type pkcs12-entry-types
	    
	    pkcs12-keystore-private-key-ref
	    pkcs12-keystore-private-key-set!
	    pkcs12-keystore-certificate-ref
	    pkcs12-keystore-certificate-set!

	    pkcs12-keystore-add-attribute!
	    
	    pkcs12-mac-descriptor? make-pkcs12-mac-descriptor

	    ;; For Java trusted cert...
	    make-java-trusted-certificate-id-attribute

	    ;; For whatever the reason...
	    *pkcs12-pbe/sha1-and-des3-cbc*
	    *pkcs12-pbe/sha1-and-des2-cbc*
	    *pkcs12-pbe/sha1-and-rc2-128-cbc*
	    *pkcs12-pbe/sha1-and-rc2-40-cbc*
	    *pbes2-aes256-cbc-pad/hmac-sha256*
	    )
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen conditions)
	    (springkussen cms)
	    (springkussen cipher password)
	    (springkussen digest)
	    (springkussen mac)
	    (springkussen random)
	    (springkussen signature)
	    (except (springkussen x509) make-x509-time make-x509-validity)
	    (springkussen x509 types) ;; for algorithm-identifier?
	    (springkussen misc bytevectors)
	    (springkussen misc lambda)
	    (springkussen misc record))

;;;; PKCS 12 keystore APIs
(define-record-type pkcs12-mac-descriptor
  (fields md iteration)
  (protocol (lambda (p)
	      (lambda/typed ((digest digest-descriptor?)
			     (iteration integer?))
	       (p digest iteration)))))
(define default-mac-descriptor
  (make-pkcs12-mac-descriptor *digest:sha256* 1024))

(define-enumeration pkcs12-entry-type
  (private-key certificate crl secret-key safe-contents unknown)
  pkcs12-entry-types)
(define *entry-types* (enum-set-universe (pkcs12-entry-types)))
(define make-entry-types (enum-set-constructor *entry-types*))

;; Should we make different record for password based and public key based
;; identify mode?
(define-record-type pkcs12-keystore
  (fields private-keys ;; both keyBag and pkcs8ShroudedKeyBag
	  certificates ;; certBag
	  crls	       ;; crlBag
	  secret-keys  ;; secretBag
	  safe-contents ;; safeContentBag
	  unknowns	;; unknown entry (maybe extension?)
	  aliases	;; key = alias, value = (local-id entry-types ...)
	  mac-descriptor
	  prng))

(define-syntax pkcs12-keystore-builder
  (make-record-builder pkcs12-keystore
   ((private-keys (make-hashtable string-ci-hash string-ci=?))
    (certificates (make-hashtable string-ci-hash string-ci=?))
    (crls (make-hashtable string-ci-hash string-ci=?))
    (secret-keys (make-hashtable string-ci-hash string-ci=?))
    (safe-contents (make-hashtable string-ci-hash string-ci=?))
    (unknowns (make-hashtable string-ci-hash string-ci=?))
    (aliases (make-hashtable string-ci-hash string-ci=?))
    (mac-descriptor default-mac-descriptor)
    (prng default-random-generator))))

(define read-pkcs12-keystore
  (case-lambda/typed
   ((password) (read-pkcs12-keystore (current-input-port) password))
   (((in (and input-port? binary-port?))
     (password string?))
    (pfx->pkcs12-keystore (read-pfx in) password))))
(define (bytevector->pkcs12-keystore bv password)
  (read-pkcs12-keystore (open-bytevector-input-port bv) password))

(define write-pkcs12-keystore
  (case-lambda/typed
   ((keystore password)
    (write-pkcs12-keystore keystore (current-output-port) password))
   ((keystore out password)
    (write-pkcs12-keystore keystore out password
			   *pbes2-aes256-cbc-pad/hmac-sha256*))
   (((keystore pkcs12-keystore?)
     (out (and output-port? binary-port?))
     (password string?)
     algorithm)
    (write-asn1-object (pkcs12-keystore->pfx keystore password algorithm)
		       out))))
(define (pkcs12-keystore->bytevector keystore password)
  (let-values (((out e) (open-bytevector-output-port)))
    (write-pkcs12-keystore keystore out password)
    (e)))

(define pkcs12-keystore-private-key-ref
  (case-lambda/typed
   ((keystore alias) (pkcs12-keystore-private-key-ref keystore alias #f))
   (((keystore pkcs12-keystore?)
     (alias string?)
     (password (or #f string?)))
    (define (decrypt key)
      (when (and (cms-encrypted-private-key-info? key) (not password))
	(springkussen-error 'pkcs12-keystore-private-key-ref
			    "Key is encrypted but no password is provided"))
      (if (cms-encrypted-private-key-info? key)
	  (let ((aid (cms-encrypted-private-key-info-encryption-algorithm key))
		(data (cms-encrypted-private-key-info-encrypted-data key)))
	    (let-values (((cipher param)
			  (algorithm-identifier->pbe-cipher&parameter aid)))
	      (bytevector->cms-private-key-info
	       (symmetric-cipher:decrypt-bytevector
		cipher (make-pbe-key password)
		param (der-octet-string-value data)))))
	  ;; non-encrypted private-key
	  key))
    (let ((private-keys (pkcs12-keystore-private-keys keystore)))
      (cond ((hashtable-ref private-keys alias #f) =>
	     (lambda (key)
	       (cms-one-asymmetric-key->private-key
		(decrypt (safe-bag-bag-value key)))))
	    (else #f))))))

(define pkcs12-keystore-private-key-set!
  (case-lambda/typed
   ((keystore alias key)
    (pkcs12-keystore-private-key-set! keystore alias key #f))
   ((keystore alias key password)
    (pkcs12-keystore-private-key-set! keystore alias key password
				      *pbes2-aes256-cbc-pad/hmac-sha256*))
   (((keystore pkcs12-keystore?)
     (alias string?)
     (key private-key?)
     (password (or #f string?))
     encryption-algorithm)
    (define (encrypt keystore alg pki password)
      (define prng (pkcs12-keystore-prng keystore))
      (let ((bv (asn1-object->bytevector pki)))
	(let-values (((data aid) (encrypt-bytevector alg prng bv password)))
	  ;; make sure we have pure ASN.1 object, without encodable
	  (make-cms-encrypted-private-key-info
	   aid
	   (make-der-octet-string data)))))
    (define (->entry pki password alias local-id)
      (define attrs (make-pkcs12-attributes alias local-id))
      (if password
	  (make-pkcs8-shrouded-key-safe-bag
	   (encrypt keystore encryption-algorithm pki password) attrs)
	  (make-key-safe-bag pki attrs)))
    (let ((pki (private-key->cms-private-key-info key))
	  (local-id (pkcs12-keystore-add-local-id! keystore alias 'private-key))
	  (private-keys (pkcs12-keystore-private-keys keystore)))
      
      (hashtable-set! private-keys alias
		      (->entry pki password alias local-id))))))

(define/typed (pkcs12-keystore-certificate-ref (keystore pkcs12-keystore?)
					      (alias string?))
  (cond ((hashtable-ref (pkcs12-keystore-certificates keystore) alias #f) =>
	 (lambda (bag) (cert-bag-cert-value (safe-bag-bag-value bag))))
	(else #f)))
(define/typed (pkcs12-keystore-certificate-set! (keystore pkcs12-keystore?)
						(alias string?)
						(cert x509-certificate?))
  (define (->entry ks cert alias)
    (let* ((local-id (pkcs12-keystore-add-local-id! ks alias 'certificate))
	   (attrs (make-pkcs12-attributes alias local-id)))
      (make-cert-safe-bag (make-x509-cert-bag cert) attrs)))

  (hashtable-set! (pkcs12-keystore-certificates keystore) alias
		  (->entry keystore cert alias)))

(define (entry-types? v)
  (if (list? v)
      (entry-types? (make-entry-types v))
      (enum-set-subset? v *entry-types*)))
(define (entry-types->storages ks entry-types)
  (define (entry-type->storage ks entry-type)
    ((case entry-type
       ((private-key)   pkcs12-keystore-private-keys)
       ((certificate)   pkcs12-keystore-certificates)
       ((crl)           pkcs12-keystore-crls)
       ((secret-key)    pkcs12-keystore-secret-keys)
       ((safe-contents) pkcs12-keystore-safe-contents)
       ((unknown)       pkcs12-keystore-unknowns)
       (else (springkussen-assertion-violation 'entry-type->storage
	       "Unknown entry type" entry-type))) ks))
  (if (pair? entry-types)
      (map (lambda (et) (entry-type->storage ks et)) entry-types)
      (entry-types->storages ks (enum-set->list entry-types))))

(define pkcs12-keystore-add-attribute!
  (case-lambda/typed
   (((keystore pkcs12-keystore?) (alias string?) attribute)
    (cond ((hashtable-ref (pkcs12-keystore-aliases keystore) alias #f) =>
	   (lambda (slot)
	     (pkcs12-keystore-add-attribute! keystore alias
					     (make-entry-types (cdr slot))
					     attribute)))))
   (((keystore pkcs12-keystore?)
     (alias string?)
     (entry-types entry-types?)
     (attribute pkcs12-attribute?))
    (for-each (lambda (storage)
		(cond ((hashtable-ref storage alias #f) =>
		       (lambda (bag) (safe-bag-add-attribute! bag attribute)))))
	      (entry-types->storages keystore entry-types)))))

(define *pbes2-oid* (make-der-object-identifier "1.2.840.113549.1.5.13"))
(define (ensure-asn1-object o)
  (bytevector->asn1-object (asn1-object->bytevector o)))
(define (make-pbes2-algorithm-identifier-provider md salt-size iter dk-len enc)
  (lambda (prng)
    (let* ((salt (random-generator:read-random-bytes prng salt-size))
	   (iv-size (symmetric-scheme-descriptor-block-size enc))
	   (iv (random-generator:read-random-bytes prng iv-size)))
      (make-algorithm-identifier *pbes2-oid*
       (ensure-asn1-object
	(make-pbes2-parameter
	 (make-pbes2-kdf-parameter salt iter dk-len md)
	 (make-pbes2-encryption-scheme enc iv)))))))
(define *pbes2-aes256-cbc-pad/hmac-sha256*
  (make-pbes2-algorithm-identifier-provider *digest:sha256* 16 1000 32
					    *scheme:aes-256*))

(define (make-pbe-algorithm-identifier-provider oid salt-size iter)
  (define der-oid (make-der-object-identifier oid))
  (lambda (prng)
    (let ((salt (random-generator:read-random-bytes prng salt-size)))
      (make-algorithm-identifier der-oid
       (ensure-asn1-object
	(make-pbe-parameter (make-der-octet-string salt)
			    (make-der-integer iter)))))))
(define *pkcs12-pbe/sha1-and-des3-cbc*
  (make-pbe-algorithm-identifier-provider "1.2.840.113549.1.12.1.3" 20 1000))
(define *pkcs12-pbe/sha1-and-des2-cbc*
  (make-pbe-algorithm-identifier-provider "1.2.840.113549.1.12.1.4" 20 1000))
(define *pkcs12-pbe/sha1-and-rc2-128-cbc*
  (make-pbe-algorithm-identifier-provider "1.2.840.113549.1.12.1.5" 20 1000))
(define *pkcs12-pbe/sha1-and-rc2-40-cbc*
  (make-pbe-algorithm-identifier-provider "1.2.840.113549.1.12.1.6" 20 1000))

;;;; Internal APIs
(define (pkcs12-keystore-add-local-id! keystore alias type)
  (define aliases (pkcs12-keystore-aliases keystore))
  (define prng (pkcs12-keystore-prng keystore))
  (hashtable-update! aliases alias
		     (lambda (v)
		       (if v
			   (cons (car v) (cons type (cdr v)))
			   (list (random-generator:read-random-bytes prng 16)
				 type)))
		     #f)
  ;; A bit wasteful, but R6RS hashtable-update! returns unspecified values...
  (car (hashtable-ref aliases alias #f)))

(define (pfx->pkcs12-keystore pfx password)
  (let* ((mac-descriptor (pfx:verify-mac pfx password))
	 ;; This decrypts encrypted data content info
	 ;; We assume cms-data-content-info contains
	 ;; trusted certificates and encrypted data contains
	 ;; key information
	 (bags (pfx->bags pfx password))
	 (keystore (pkcs12-keystore-builder (mac-descriptor mac-descriptor))))
    ;; (for-each describe-asn1-object bags)
    (for-each (lambda (bag) (process-bag! keystore bag)) bags)
    keystore))

(define (process-bag! keystore bag)
  (define (entry-type&storage keystore bag)
    (cond ((key-safe-bag? bag)
	   (values 'private-key (pkcs12-keystore-private-keys keystore)))
	  ((pkcs8-shrouded-key-safe-bag? bag)
	   (values 'private-key (pkcs12-keystore-private-keys keystore)))
	  ((cert-safe-bag? bag)
	   (values  'certificate (pkcs12-keystore-certificates keystore)))
	  ((crl-safe-bag? bag)
	   (values 'crl (pkcs12-keystore-crls keystore)))
	  ((secret-safe-bag? bag)
	   (values 'secret-key (pkcs12-keystore-secret-keys keystore)))
	  ;; nested bag, let the user handle it
	  ((safe-contents-safe-bag? bag)
	   (values 'safe-contents (pkcs12-keystore-safe-contents keystore)))
	  ((safe-bag? bag)
	   (values 'unknown (pkcs12-keystore-unknowns keystore)))
	  (else
	   (springkussen-error 'process-bag! "Unknown bag type" bag))))
  (define (store-bag keystore attribute value entry-type storage)
    (define (finish keystore storage value local-id alias)
      (define prng (pkcs12-keystore-prng keystore))
      (define (ensure-alias alias)
	(or alias
	    (let ((random-name (random-generator:read-random-bytes prng 16)))
	      (hashtable-set! storage random-name value)
	      (bytevector->hex-string random-name))))
      (let ((alias (ensure-alias alias))
	    (local-id (or local-id
			  (random-generator:read-random-bytes prng 16)))
	    (aliases (pkcs12-keystore-aliases keystore)))
	;; alias = (local-id . (entry-type ...))
	(hashtable-update! aliases alias
			   (lambda (v) (cons (car v) (cons entry-type (cdr v))))
			   (list local-id))))
    (let loop ((a* (if attribute (asn1-collection-elements attribute) '()))
	       (alias #f)
	       (local-id #f))
      (if (null? a*)
	  (finish keystore storage value local-id alias)
	  (let* ((a (car a*)) (v (pkcs12-attribute-attr-values a)))
	    (cond ((pkcs12-friendly-name-attribute? a)
		   (let ((name (der-bmp-string-value
				(car (asn1-collection-elements v)))))
		     (hashtable-set! storage name value)
		     (loop (cdr a*) name local-id)))
		  ((pkcs12-local-key-id-attribute? a)
		   (loop (cdr a*) alias (der-octet-string-value
					 (car (asn1-collection-elements v)))))
		  ;; ignore
		  (else (loop (cdr a*) alias local-id)))))))
  (let ((attributes (safe-bag-bag-attributes bag)))
    (let-values (((entry-type storage) (entry-type&storage keystore bag)))
      (store-bag keystore attributes bag entry-type storage))))

(define (pkcs12-keystore->pfx ks password alg)
  (define (hashtable->bags ht aliases)
    (let-values (((keys values) (hashtable-entries ht)))
      (vector->list values)))
  (define (encrypt-content ks content)
    (define prng (pkcs12-keystore-prng ks))
    (define bv (asn1-object->bytevector content))
    (let-values (((data aid) (encrypt-bytevector alg prng bv password)))
      (make-cms-encrypted-content-info
       (make-der-object-identifier "1.2.840.113549.1.7.1")
       aid
       (make-der-octet-string data))))
  
  (define aliases (pkcs12-keystore-aliases ks))
  (define private-keys (pkcs12-keystore-private-keys ks))
  (define secret-keys (pkcs12-keystore-secret-keys ks))
  (define safe-contents (pkcs12-keystore-safe-contents ks))
  (define certificates (pkcs12-keystore-certificates ks))
  (define crls (pkcs12-keystore-crls ks))
  (define unknowns (pkcs12-keystore-unknowns ks))
  (define mac-descriptor (pkcs12-keystore-mac-descriptor ks))
  (define prng (pkcs12-keystore-prng ks))
  
  (let* ((encrypted-bags (cms-encrypted-data->content-info
			  (make-cms-encrypted-data
			   (make-der-integer 0)
			   (encrypt-content ks
			    (make-der-sequence
			     (append
			      (hashtable->bags private-keys aliases)
			      (hashtable->bags secret-keys aliases)
			      (hashtable->bags certificates aliases)
			      (hashtable->bags crls aliases)
			      (hashtable->bags safe-contents aliases)
			      (hashtable->bags unknowns aliases))))
			   #f)))
	 (mac-data (asn1-object->bytevector (der-sequence encrypted-bags)))
	 (auth-safe (der-octet-string->content-info
		     (make-der-octet-string mac-data)))
	 (md (pkcs12-mac-descriptor-md mac-descriptor))
	 (c (pkcs12-mac-descriptor-iteration mac-descriptor))
	 (salt (random-generator:read-random-bytes
		prng (digest-descriptor-digest-size md)))
	 (mac (compute-mac md mac-data password salt c)))
    
    (make-pfx (make-der-integer 3) auth-safe
	      (make-mac-data
	       (make-digest-info
		(make-algorithm-identifier
		 (make-der-object-identifier (digest-descriptor-oid md)))
		(make-der-octet-string mac))
	       (make-der-octet-string salt)
	       (make-der-integer c)))))

(define (encrypt-bytevector alg prng bv password)
  (let ((key (make-pbe-key password))
	(aid (alg prng)))
    (let-values (((c p) (algorithm-identifier->pbe-cipher&parameter aid)))
      (values (symmetric-cipher:encrypt-bytevector c key p bv)
	      aid))))

(define (algorithm-identifier->pbe-cipher&parameter aid)
  (define oid (algorithm-identifier-algorithm aid))
  (define param (algorithm-identifier-parameters aid))
  ;; PBES2
  (if (string=? (der-object-identifier-value oid) "1.2.840.113549.1.5.13")
      (let ((pbes2-parameter (asn1-object->pbes2-parameter param)))
	(pbes2-parameter->pbe-cipher&parameter pbes2-parameter))
      ;; Assuem PBES1
      (aid->cipher&key-parameter aid)))
	

;;;; Internal implementation

;;;; 4.  PFX PDU Syntax
;; PFX ::= SEQUENCE {
;;     version     INTEGER {v3(3)}(v3,...),
;;     authSafe    ContentInfo,
;;     macData     MacData OPTIONAL
;; }
(define-record-type pfx
  (parent <asn1-encodable-object>)
  (fields version auth-safe mac-data)
  (protocol (lambda (n)
	      (define (version3? v)
		(and (der-integer? v)
		     (= (der-integer-value v) 3)))
	      (lambda/typed ((version version3?)
			     (auth-safe cms-content-info?)
			     (mac-data (or #f mac-data?)))
	        ((n simple-asn1-encodable-object->der-sequence)
		 version auth-safe mac-data)))))

(define/typed (asn1-object->pfx (asn1-object der-sequence?))
  (let ((e (asn1-collection-elements asn1-object)))
    (unless (= (length e) 3)
      (springkussen-assertion-violation 'asn1-object->pfx "Invalid format"))
    (make-pfx (car e)
	      (asn1-object->cms-content-info (cadr e))
	      (asn1-object->mac-data (caddr e)))))

(define/typed (pfx->bags (pfx pfx?) (password string?))
  (define (safe->bag safe)
    (cond ((cms-encrypted-data-content-info? safe)
	   (pfx:decrypt-encrypted-content safe password))
	  ((cms-data-content-info? safe)
	   (map asn1-object->safe-bag
		(asn1-collection-elements
		 (bytevector->asn1-object
		  (der-octet-string-value
		   (cms-data-content-info:content safe))))))
	  (else
	   (list safe))))
  (let ((safes (pfx->authenticated-safes pfx)))
    (apply append (map safe->bag safes))))

(define/typed (pfx->authenticated-safes (pfx pfx?))
  (define (octet-string->safes content)
    (let ((s (bytevector->asn1-object (der-octet-string-value content))))
      (unless (der-sequence? s)
	(springkussen-error 'pfx->authenticated-safes
			    "Invalid format of PFX" pfx))
      (map asn1-object->cms-content-info (asn1-collection-elements s))))
  (let ((content (cms-content-info-content (pfx-auth-safe pfx))))
    (cond ((der-octet-string? content) ;; password integrity mode
	   (octet-string->safes content))
	  ((cms-signed-data? content) ;; public-key integrity mode
	   (let* ((encap (cms-signed-data-encap-content-info content))
		  (content (cms-content-handler
			    (cms-encapsulated-content-info-e-content-type encap)
			    (cms-encapsulated-content-info-e-content encap))))
	     ;; content must be data?
	     (octet-string->safes content)))
	  (else
	   (springkussen-error 'pfx->authenticated-safes "Unknown mode" pfx)))))

(define/typed (pfx:decrypt-encrypted-content
	       (info cms-encrypted-data-content-info?)
	       (password string?))
  (let ((aid (cms-enctypted-data-content-info:encryption-algorithm info)))
    (let-values (((cipher parameter) (aid->cipher&key-parameter aid)))
      (let* ((bv (cms-enctypted-data-content-info:decrypt-content
		  info cipher (make-pbe-key password) parameter))
	     (asn1-object (bytevector->asn1-object bv)))
	(unless (der-sequence? asn1-object)
	  (springkussen-error 'pfx:decrypt-encrypted-content
			      "Unknown encrypted data"))
	(map asn1-object->safe-bag (asn1-collection-elements asn1-object))))))

(define *digest-oids*
  (map (lambda (md) (cons (digest-descriptor-oid md) md))
       *supporting-digests*))

(define/typed (pfx:verify-mac (pfx pfx?) (password string?))
  (define (aid->digest aid)
    (define oid (algorithm-identifier-algorithm aid))
    (cond ((assoc (der-object-identifier-value oid) *digest-oids*) => cdr)
	  (else (springkussen-error 'pfx:verify-mac
				    "Unsupported digest"
				    (der-object-identifier-value oid)))))
  (define content (cms-content-info-content (pfx-auth-safe pfx)))
  (let* ((mac-data (pfx-mac-data pfx))
	 (mac (mac-data-mac mac-data))
	 (salt (der-octet-string-value (mac-data-mac-salt mac-data)))
	 (c (der-integer-value (mac-data-iterations mac-data)))
	 (aid (digest-info-digest-algorithm mac))
	 (digest (der-octet-string-value (digest-info-digest mac)))
	 (data (der-octet-string-value content))
	 (md (aid->digest aid)))
    (unless (bytevector-safe=? digest (compute-mac md data password salt c))
      (springkussen-error 'pfx:verify-mac
	"MAC of the ContentInfo is invalid - wrong password or corrupted file."
	pfx))
    (make-pkcs12-mac-descriptor md c)))
  
(define (compute-mac md data password salt iterations)
  (let* ((mac-key (derive-mac-key md password salt iterations))
	 (hmac (make-mac *mac:hmac* (make-hmac-parameter mac-key md))))
    (mac:generate-mac hmac data)))
    
(define read-pfx
  (case-lambda
   (() (read-pfx (current-input-port)))
   ((in) (asn1-object->pfx (read-asn1-object in)))))

(define (bytevector->pfx bv) (read-pfx (open-bytevector-input-port bv)))

(define write-pfx
  (case-lambda
   ((pfx) (write-pfx pfx (current-output-port)))
   ((pfx out) (write-asn1-object pfx out))))

(define/typed (pfx->bytevector (pfx pfx?))
  (asn1-object->bytevector pfx))

;; MacData ::= SEQUENCE {
;;     mac         DigestInfo,
;;     macSalt     OCTET STRING,
;;     iterations  INTEGER DEFAULT 1
;;     -- Note: The default is for historical reasons and its
;;     --       use is deprecated.
;; }
(define-record-type mac-data
  (parent <asn1-encodable-object>)
  (fields mac mac-salt iterations)
  (protocol (lambda (n)
	      (case-lambda/typed
	       (((mac digest-info?) (mac-salt der-octet-string?))
		((n simple-asn1-encodable-object->der-sequence)
		 mac mac-salt (make-der-integer 1)))
	       (((mac digest-info?) (mac-salt der-octet-string?)
		 (iterations der-integer?))
		((n simple-asn1-encodable-object->der-sequence)
		 mac mac-salt iterations))))))

(define/typed (asn1-object->mac-data (asn1-object der-sequence?))
  (let ((e (asn1-collection-elements asn1-object)))
    (apply make-mac-data (asn1-object->digest-info (car e)) (cdr e))))

;; DigestInfo from https://datatracker.ietf.org/doc/html/rfc2315#section-9.4
;;  Apparently, PFX uses old PKCS#7 DigetInfo which isn't defined
;;  in CMS (RFC-5652) anymore.
;; 
;; DigestInfo ::= SEQUENCE {
;;   digestAlgorithm DigestAlgorithmIdentifier,
;;   digest Digest }
;;
;; Digest ::= OCTET STRING
(define-record-type digest-info
  (parent <asn1-encodable-object>)
  (fields digest-algorithm digest)
  (protocol (lambda (n)
	      (lambda/typed ((digest-algorithm algorithm-identifier?)
			     (digest der-octet-string?))
	        ((n simple-asn1-encodable-object->der-sequence)
		 digest-algorithm digest)))))

(define/typed (asn1-object->digest-info (asn1-object der-sequence?))
  (let ((e (asn1-collection-elements asn1-object)))
    (make-digest-info (asn1-object->algorithm-identifier (car e)) (cadr e))))

;; SafeContents ::= SEQUENCE OF SafeBag
;;
;; SafeBag ::= SEQUENCE {
;;     bagId          BAG-TYPE.&id ({PKCS12BagSet})
;;     bagValue       [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
;;     bagAttributes  SET OF PKCS12Attribute OPTIONAL
;; }
(define-record-type safe-bag
  (parent <asn1-encodable-object>)
  (fields bag-id bag-value (mutable bag-attributes))
  (protocol (lambda (n)
	      (lambda/typed ((bag-id der-object-identifier?)
			     (bag-value asn1-object?)
			     (bag-attribute
			      (or #f (der-set-of? pkcs12-attribute?))))
	        ((n safe-bag->asn1-object) bag-id bag-value bag-attribute)))))

(define/typed (safe-bag-add-attribute! (safe-bag safe-bag?)
				       (attribute pkcs12-attribute?))
  (define (ensure-attrs safe-bag)
    (let ((attrs (safe-bag-bag-attributes safe-bag)))
      (or attrs
	  (let ((set (der-set)))
	    (safe-bag-bag-attributes-set! safe-bag set)
	    set))))
  (let ((attrs (ensure-attrs safe-bag)))
    (der-set:add! attrs attribute)))

(define *key-bag-id* (make-der-object-identifier "1.2.840.113549.1.12.10.1.1"))
(define *pkcs8-shrouded-key-bag-id*
  (make-der-object-identifier "1.2.840.113549.1.12.10.1.2"))
(define *cert-bag-id* (make-der-object-identifier "1.2.840.113549.1.12.10.1.3"))
(define *crl-bag-id* (make-der-object-identifier "1.2.840.113549.1.12.10.1.4"))
(define *secret-bag-id*
  (make-der-object-identifier "1.2.840.113549.1.12.10.1.5"))
(define *safe-contents-bag-id*
  (make-der-object-identifier "1.2.840.113549.1.12.10.1.5"))
(define-syntax define-concrete-safe-bag
  (syntax-rules ()
    ((_ name oid value-type?)
     (define-record-type name
       (parent safe-bag)
       (protocol (lambda (n)
		   (lambda/typed ((bag-value value-type?)
				  (bag-attribute
				   (or #f (der-set-of? pkcs12-attribute?))))
		    ((n oid bag-value bag-attribute)))))))))
(define-concrete-safe-bag key-safe-bag *key-bag-id* cms-private-key-info?)
(define-concrete-safe-bag pkcs8-shrouded-key-safe-bag
  *pkcs8-shrouded-key-bag-id* cms-encrypted-private-key-info?)
(define-concrete-safe-bag cert-safe-bag *cert-bag-id* cert-bag?)
(define-concrete-safe-bag crl-safe-bag *crl-bag-id* crl-bag?)
(define-concrete-safe-bag secret-safe-bag *secret-bag-id* secret-bag?)
(define-concrete-safe-bag safe-contents-safe-bag *safe-contents-bag-id*
  der-sequence?)

(define (safe-bag->asn1-object self)
  (make-der-sequence
   (filter values (list (safe-bag-bag-id self)
			(make-der-tagged-object 0 #t (safe-bag-bag-value self))
			(safe-bag-bag-attributes self)))))

(define/typed (asn1-object->safe-bag (asn1-object der-sequence?))
  (let ((e (asn1-collection-elements asn1-object)))
    (when (< (length e) 2)
      (springkussen-assertion-violation 'asn1-object->safe-bag
					"Invalid format"))
    (let* ((id (car e))
	   (attrs (and (not (null? (cddr e))) (caddr e))))
      (handle-safe-bag id
       (and attrs 
	    (make-der-set
	     (map asn1-object->pkcs12-attribute
		  (asn1-collection-elements attrs))))
       (der-tagged-object-obj (cadr e))))))

;; PKCS12Attribute ::= SEQUENCE {
;;     attrId      ATTRIBUTE.&id ({PKCS12AttrSet}),
;;     attrValues  SET OF ATTRIBUTE.&Type ({PKCS12AttrSet}{@attrId})
;; } -- This type is compatible with the X.500 type 'Attribute'
;;
;; PKCS12AttrSet ATTRIBUTE ::= {
;;     friendlyName | -- from PKCS #9 [23]
;;     localKeyId,    -- from PKCS #9
;;     ... -- Other attributes are allowed
;; }
(define-record-type pkcs12-attribute
  (parent <asn1-encodable-object>)
  (fields attr-id (mutable attr-values))
  (protocol (lambda (n)
	      (lambda/typed ((attr-id der-object-identifier?)
			     (attr-values (der-set-of? asn1-object?)))
	        ((n simple-asn1-encodable-object->der-sequence)
		 attr-id attr-values)))))
(define *pkcs-9-at-friendly-name*
  (make-der-object-identifier "1.2.840.113549.1.9.20"))
(define-record-type pkcs12-friendly-name-attribute
  (parent pkcs12-attribute)
  (protocol (lambda (n)
	      (lambda/typed ((name der-bmp-string?))
	        ((n *pkcs-9-at-friendly-name* (der-set name)))))))

(define *pkcs-9-at-local-key-id*
  (make-der-object-identifier "1.2.840.113549.1.9.21"))
(define-record-type pkcs12-local-key-id-attribute
  (parent pkcs12-attribute)
  (protocol (lambda (n)
	      (lambda/typed ((local-key-id der-octet-string?))
	        ((n *pkcs-9-at-local-key-id* (der-set local-key-id)))))))
;; If we want to make our library usable for JVM, we must also support
;; this more or less proprietary OID, which is not even registered OID ref
(define *java-trusted-certificate-id*
  (make-der-object-identifier "2.16.840.1.113894.746875.1.1"))
(define *any-extended-key-usage* (make-der-object-identifier "2.5.29.37.0"))
(define-record-type java-trusted-certificate-id-attribute
  (parent pkcs12-attribute)
  (protocol (lambda (n)
	      (lambda ()
	        ((n *java-trusted-certificate-id*
		    (der-set *any-extended-key-usage*)))))))

(define (make-pkcs12-attributes alias local-id)
  (der-set
   (make-pkcs12-friendly-name-attribute (make-der-bmp-string alias))
   (make-pkcs12-local-key-id-attribute (make-der-octet-string local-id))))

(define/typed (asn1-object->pkcs12-attribute (asn1-object der-sequence?))
  (let ((e (asn1-collection-elements asn1-object)))
    (unless (= (length e) 2)
      (springkussen-assertion-violation 'asn1-object->pkcs12-attribute
					"Invalid format"))
    (let ((oid (car e)) (set (cadr e)))
      (unless (and (der-object-identifier? oid) (der-set? set))
	(springkussen-assertion-violation 'asn1-object->pkcs12-attribute
					  "Invalid format"))
      (cond ((asn1-object=? oid *pkcs-9-at-friendly-name*)
	     (make-pkcs12-friendly-name-attribute
	      (car (asn1-collection-elements set))))
	    ((asn1-object=? oid *pkcs-9-at-local-key-id*)
	     (make-pkcs12-local-key-id-attribute
	      (car (asn1-collection-elements set))))
	    ((asn1-object=? oid *java-trusted-certificate-id*)
	     (make-java-trusted-certificate-id-attribute))
	    (else (make-pkcs12-attribute oid set))))))

(define (handle-safe-bag id attrs asn1-object)
  (define oid (der-object-identifier-value id))

  (cond ((string=? oid "1.2.840.113549.1.12.10.1.1")
	 (make-key-safe-bag (asn1-object->key-bag asn1-object) attrs))
	((string=? oid "1.2.840.113549.1.12.10.1.2")
	 (make-pkcs8-shrouded-key-safe-bag
	  (asn1-object->pkcs8-shrouded-bag asn1-object) attrs))
	((string=? oid "1.2.840.113549.1.12.10.1.3")
	 (make-cert-safe-bag (asn1-object->cert-bag asn1-object) attrs))
	((string=? oid "1.2.840.113549.1.12.10.1.4")
	 (make-crl-safe-bag (asn1-object->crl-bag asn1-object) attrs))
	((string=? oid "1.2.840.113549.1.12.10.1.5")
	 (make-secret-safe-bag (asn1-object->secret-bag asn1-object) attrs))
	((string=? oid "1.2.840.113549.1.12.10.1.6")
	 ;; sort of type conversion?
	 (make-safe-contents-safe-bag
	  (make-der-sequence
	   (map asn1-object->safe-bag (asn1-collection-elements asn1-object)))
	  attrs))
	;; unknown, let it be
	(else (make-safe-bag id asn1-object attrs))))

;; KeyBag ::= PrivateKeyInfo
(define (asn1-object->key-bag asn1-object)
  (asn1-object->cms-private-key-info asn1-object))

;; PKCS8ShroudedKeyBag ::= EncryptedPrivateKeyInfo
(define (asn1-object->pkcs8-shrouded-bag asn1-object)
  (asn1-object->cms-encrypted-private-key-info asn1-object))

;; CertBag ::= SEQUENCE {
;;     certId      BAG-TYPE.&id   ({CertTypes}),
;;     certValue   [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId})
;; }
(define-record-type cert-bag
  (parent <asn1-encodable-object>)
  (fields cert-id cert-value)
  (protocol (lambda (n)
	      (case-lambda/typed
	       (((cert-id der-object-identifier?)
		 (cert-value asn1-object?))
	        ((n cert-bag->asn1-object) cert-id cert-value))
	       ((->asn1-object
		 (cert-id der-object-identifier?)
		 (cert-value asn1-object?))
	        ((n ->asn1-object) cert-id cert-value))))))
(define (cert-bag->asn1-object self)
  (der-sequence (cert-bag-cert-id self)
		(make-der-tagged-object 0 #t (cert-bag-cert-value self))))

(define pkcs12-x509-certificate-oid
  (make-der-object-identifier "1.2.840.113549.1.9.22.1"))
(define pkcs12-sdsi-certificate-oid
  (make-der-object-identifier "1.2.840.113549.1.9.22.2"))
(define-record-type x509-cert-bag
  (parent cert-bag)
  (protocol (lambda (n)
	      (lambda/typed ((cert x509-certificate?))
	        ((n x509-cert-bag->asn1-object 
		    pkcs12-x509-certificate-oid cert))))))
(define (x509-cert-bag->asn1-object self)
  (der-sequence
   pkcs12-x509-certificate-oid
   (make-der-tagged-object 0 #t
    (make-der-octet-string
     (x509-certificate->bytevector (cert-bag-cert-value self))))))

(define-record-type sdsi-cert-bag
  (parent cert-bag)
  (protocol (lambda (n)
	      (lambda/typed ((cert asn1-object?))
	        ((n pkcs12-sdsi-certificate-oid cert))))))

(define/typed (asn1-object->cert-bag (asn1-object der-sequence?))
  (define (err)
    (springkussen-assertion-violation 'cert-bag->asn1-object "Invalid format"))
  (let ((e (asn1-collection-elements asn1-object)))
    (unless (= (length e) 2) (err))
    (let ((id (car e)) (value (cadr e)))
      (unless (der-object-identifier? id) (err))
      (unless (der-tagged-object? value) (err))
      (unless (zero? (der-tagged-object-tag-no value)) (err))
      (let ((v (der-tagged-object-obj value)))
	(cond ((asn1-object=? pkcs12-x509-certificate-oid id)
	       (make-x509-cert-bag (bytevector->x509-certificate
				    (der-octet-string-value v))))
	      ;; Never seen SDSI certificate, so just put it as it is...
	      ((asn1-object=? pkcs12-sdsi-certificate-oid id)
	       (make-sdsi-cert-bag v))
	      ;; unknown bare cert bag
	      (else (make-cert-bag id v)))))))

;; CRLBag ::= SEQUENCE {
;;     crlId      BAG-TYPE.&id  ({CRLTypes}),
;;     crlValue  [0] EXPLICIT BAG-TYPE.&Type ({CRLTypes}{@crlId})
;; }
;;
;; x509CRL BAG-TYPE ::=
;;     {OCTET STRING IDENTIFIED BY {crlTypes 1}}
;;     -- DER-encoded X.509 CRL stored in OCTET STRING
;;
;; CRLTypes BAG-TYPE ::= {
;;     x509CRL,
;;     ... -- For future extensions
;; }
(define-record-type crl-bag
  (parent <asn1-encodable-object>)
  (fields crl-id crl-value)
  (protocol (lambda (n)
	      (lambda/typed ((crl-id der-object-identifier?)
			     ;; There's no other and we don't consider future
			     ;; extension for now...
			     (crl-value x509-certificate-revocation-list?))
	        ((n crl-bag->asn1-object) crl-id crl-value)))))
(define (crl-bag->asn1-object self)
  (der-sequence
   (crl-bag-crl-id self)
   (make-der-tagged-object 0 #t
    (make-der-octet-string 
     (x509-certificate-revocation-list->bytevector (crl-bag-crl-value self))))))
		 
(define/typed (asn1-object->crl-bag (asn1-object der-sequence?))
  (let ((e (asn1-collection-elements asn1-object)))
    (unless (= (length e) 2)
      (springkussen-assertion-violation 'asn1-object->crl-bag
					"Invalid format"))
    (let ((obj (asn1-collection:find-tagged-object asn1-object 0)))
      (unless obj
	(springkussen-assertion-violation 'asn1-object->crl-bag
					"Invalid format"))
      (make-cert-bag (car e)
		     (bytevector->x509-certificate-revocation-list
		      (der-octet-string-value (der-tagged-object-obj obj)))))))

;; SecretBag ::= SEQUENCE {
;;     secretTypeId   BAG-TYPE.&id ({SecretTypes}),
;;     secretValue    [0] EXPLICIT BAG-TYPE.&Type ({SecretTypes}
;;                        {@secretTypeId})
;; }
;;
;; SecretTypes BAG-TYPE ::= {
;;     ... -- For future extensions
;; }
;; For now, we put secretTypeId == BAG-TYPE, following the example of
;; Keystore Explorer
(define-record-type secret-bag
  (parent <asn1-encodable-object>)
  (fields secret-type-id secret-value)
  (protocol (lambda (n)
	      (lambda/typed ((secret-type-id der-object-identifier?)
			     (secret-value asn1-object?))
	       ((n secret-bag->asn1-object) secret-type-id secret-value)))))

(define (secret-bag->asn1-object self)
  (der-sequence
   (secret-bag-secret-type-id self)
   (make-der-tagged-object 0 #t
    (make-der-octet-string
     (asn1-object->bytevector (secret-bag-secret-value self))))))

(define/typed (asn1-object->secret-bag (asn1-object der-sequence?))
  (let* ((v (asn1-collection:find-tagged-object asn1-object 0))
	 (obj (bytevector->asn1-object
	       (der-octet-string-value (der-tagged-object-obj v))))
	 (oid (car (asn1-collection-elements asn1-object))))
    (make-secret-bag oid (handle-safe-bag oid #f obj))))


(define (aid->cipher&key-parameter aid)
  (define oid
    (der-object-identifier-value (algorithm-identifier-algorithm aid)))
  ((cond ((assoc oid *oid-cipher-creator*) => cdr)
	 (else (springkussen-error 'aid->cipher&key-parameter
				   "Unknown OID" oid))) aid))

;; TODO should we make ASN.1 type for this?
(define (aid->pbe-parameter aid)
  (define param (algorithm-identifier-parameters aid))
  (define e (asn1-collection-elements param))
  (make-cipher-parameter
   (make-pbe-cipher-salt-parameter (der-object-identifier-value (car e)))
   (make-pbe-cipher-iteration-parameter (der-integer-value (cadr e)))))

(define (make-pbes1-cipher-creator scheme key-size) 
  (let ((param (make-pbe-cipher-encryption-scheme-parameter scheme))
	(kdf (make-pkcs12-kdf key-size *digest:sha1*)))
    (lambda (aid)
      (values (make-pbe-cipher *pbe:pbes1* param)
	      (make-cipher-parameter
	       (aid->pbe-parameter aid)
	       (make-pbe-cipher-key-size-parameter key-size)
	       (make-pbe-cipher-kdf-parameter kdf))))))

(define (make-pkcs12-kdf key-size md)
  (lambda (P S c dk-len)
    ;; P = UTF8 password, so make it string again...
    (define pw (utf8->string P))
    (define iv-size (- dk-len key-size)) ;; block size
    (let ((dk (derive-pkcs12-key md pw S c *key-material* key-size))
	  (iv (derive-pkcs12-key md pw S c *iv-material* iv-size)))
      (bytevector-append dk iv))))

(define *oid-cipher-creator*
  `(("1.2.840.113549.1.12.1.3" . ,(make-pbes1-cipher-creator *scheme:desede* 24))
    ("1.2.840.113549.1.12.1.4" . ,(make-pbes1-cipher-creator *scheme:desede* 16))
    ("1.2.840.113549.1.12.1.5" . ,(make-pbes1-cipher-creator *scheme:rc2* 16))
    ("1.2.840.113549.1.12.1.6" . ,(make-pbes1-cipher-creator *scheme:rc2* 5))))


;;;; Appendix B. Deriving Keys and IVs from Passwords and Salt
;;;; Appendix B.3 More on the ID Byte
(define *key-material* 1)
(define *iv-material*  2)
(define *mac-material* 3)

(define (derive-mac-key md password salt iteration)
  (derive-pkcs12-key md password salt iteration *mac-material*
		     (digest-descriptor-digest-size md)))

(define/typed (derive-pkcs12-key (md digest-descriptor?)
				 (pw string?)
				 (salt bytevector?)
				 (iteration integer?)
				 (ID integer?)
				 (n integer?))
  (define u (digest-descriptor-digest-size md))
  (define v (digest-descriptor-block-size md))
  (define password (string->utf16 (string-append pw "\x0;") (endianness big)))

  (define (adjust a a-off b)
    (let* ((b-len (bytevector-length b))
	   (i (- b-len 1))
	   (x (+ (bitwise-and (bytevector-u8-ref b i) #xFF)
		 (bitwise-and (bytevector-u8-ref a (+ a-off i)) #xFF)
		 1)))
      (define (next-x x i)
	(+ x
	   (bitwise-and (bytevector-u8-ref b i) #xFF)
	   (bitwise-and (bytevector-u8-ref a (+ a-off i)) #xFF)))
      (bytevector-u8-set! a (+ a-off i) (bitwise-and x #xFF))
      (let loop ((i (- i 1)) (x (bitwise-arithmetic-shift-right x 8)))
	(unless (< i 0)
	  (let ((x (next-x x i)))
	    (bytevector-u8-set! a (+ a-off i) (bitwise-and x #xFF))
	    (loop (- i 1) (bitwise-arithmetic-shift-right x 8)))))))
  (define (gen-SP bv)
    (let ((l (bytevector-length bv)))
      (if (zero? l)
	  #vu8()
	  (let ((len (* v (div (- (+ l v) 1) v))))
	    (do ((i 0 (+ i 1)) (r (make-bytevector len)))
		((= i len) r)
	      (bytevector-u8-set! r i (bytevector-u8-ref bv (mod i l))))))))

  (let* ((D (make-bytevector v ID))
	 (d-key (make-bytevector n 0))
	 (S (gen-SP salt))
	 (P (gen-SP password))
	 (S-len (bytevector-length S))
	 (P-len (bytevector-length P))
	 (I (make-bytevector (+ S-len P-len)))
	 (B (make-bytevector v))
	 (c (div (- (+ n u) 1) u)))
    (bytevector-copy! S 0 I 0 S-len)
    (bytevector-copy! P 0 I S-len P-len)
    (do ((i 0 (+ i 1)) (digester (make-digester md)))
	((= i c) d-key)
      (let ((A (make-bytevector u)))
	(digester:init! digester)
	(digester:process! digester D)
	(digester:process! digester I)
	(digester:done! digester A)
	(do ((j 0 (+ j 1)) (c (- iteration 1)))
	    ((= j c))
	  (digester:init! digester)
	  (digester:process! digester A)
	  (digester:done! digester A))
	(do ((j 0 (+ j 1)) (c (bytevector-length B)))
	    ((= j c))
	  (bytevector-u8-set! B j (bytevector-u8-ref A (mod j u))))
	(do ((j 0 (+ j 1)) (c (div (bytevector-length I) v)))
	    ((= j c))
	  (adjust I (* j v) B))
	(if (= i (- c 1))
	    (bytevector-copy! A 0 d-key (* i u) (- n (* i u)))
	    (bytevector-copy! A 0 d-key (* i u) u))))))
)
