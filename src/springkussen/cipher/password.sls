;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/password.sls - PBE cipher APIs
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

;; ref: https://datatracker.ietf.org/doc/html/rfc8018#section-5
#!r6rs
(library (springkussen cipher password)
    (export make-pbe-cipher-encryption-scheme-parameter
	    pbe-cipher-encryption-scheme-parameter?

	    make-pbe-cipher-kdf-parameter pbe-cipher-kdf-parameter?

	    make-pbe-cipher-salt-parameter pbe-cipher-salt-parameter?

	    make-pbe-cipher-iteration-parameter pbe-cipher-iteration-parameter?
	    
	    make-pbes2-cipher-encryption-mode-parameter
	    pbes2-cipher-encryption-mode-parameter?
	    
	    pbe-scheme-descriptor?
	    pbe-scheme-descriptor-name
	    (rename (pbes1-scheme-descriptor *pbe:pbes1*)
		    (pbes2-scheme-descriptor *pbe:pbes2*))

	    ;; key
	    (rename (make-symmetric-key make-pbe-key)
		    (symmetric-key? pbe-key?))

	    ;; KDF
	    pbe-kdf-parameter?

	    make-pbkdf-1
	    make-pbe-kdf-digest-parameter pbe-kdf-digest-parameter?
	    pbe-kdf-parameter-md ;; needed for PKCS12...

	    make-pbe-cipher-key-size-parameter pbe-cipher-key-size-parameter?
	    pbe-cipher-parameter-key-size ;; needed for PKCS12...
	    
	    
	    make-pbkdf-2
	    make-pbe-kdf-prf-parameter pbe-kdf-prf-parameter?

	    mac->pbkdf2-prf
	    make-partial-hmac-parameter

	    make-pbe-cipher

	    pbe-parameter? make-pbe-parameter asn1-object->pbe-parameter
	    pbe-parameter:salt pbe-parameter:iteration
	    pbes2-parameter? make-pbes2-parameter asn1-object->pbes2-parameter
	    make-pbes2-encryption-scheme
	    make-pbes2-kdf-parameter
	    pbes2-parameter->pbe-cipher&parameter
	    
	    ;; re-export
	    symmetric-cipher? 
	    symmetric-cipher:encrypt-bytevector
	    symmetric-cipher:decrypt-bytevector

	    symmetric-cipher-operation
	    symmetric-cipher:init!
	    symmetric-cipher:encrypt
	    symmetric-cipher:encrypt!
	    symmetric-cipher:encrypt-last-block
	    symmetric-cipher:encrypt-last-block!
	    symmetric-cipher:decrypt
	    symmetric-cipher:decrypt!
	    symmetric-cipher:decrypt-last-block
	    symmetric-cipher:decrypt-last-block!
	    symmetric-cipher:done!

	    symmetric-scheme-descriptor?
	    symmetric-scheme-descriptor-name
	    symmetric-scheme-descriptor-block-size
	    
	    *scheme:aes*
	    *scheme:aes-128*
	    *scheme:aes-192*
	    *scheme:aes-256*
	    *scheme:des*
	    *scheme:desede*
	    *scheme:rc2*
	    *scheme:rc5*

	    ;; PBE, as far as I know, only uses CBC.
	    ;; *mode:ecb* *mode:cbc*

	    make-cipher-parameter cipher-parameter?
	    mode-parameter? 
	    make-iv-paramater iv-parameter?

	    pkcs7-padding no-padding
	    )
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen conditions)
	    (springkussen cipher symmetric)
	    (springkussen cipher password kdf)
	    (springkussen cipher password scheme descriptor)
	    (springkussen cipher password scheme pbes1)
	    (springkussen cipher password scheme pbes2)
	    (springkussen digest)
	    (springkussen mac)
	    (springkussen x509 types) ;; getting silly...
	    (springkussen misc lambda))

(define (make-pbe-cipher desc param)
  (define spec (symmetric-cipher-spec-builder
		(scheme (pbe-cipher-parameter-encryption-scheme param))
		(mode desc)))
  (make-symmetric-cipher spec))

;; ASN.1 modules for PKCS#5
;; PBEParameter ::= SEQUENCE {
;;     salt OCTET STRING (SIZE(8)),
;;     iterationCount INTEGER
;; }
;; We don't check the size as we accept AES or other block ciphers as well
(define-record-type pbe-parameter
  (parent <asn1-encodable-object>)
  (fields salt iteration)
  (protocol (lambda (n)
	      (lambda/typed ((salt der-octet-string?)
			     (iteration der-integer?))
	       ((n simple-asn1-encodable-object->der-sequence) 
		salt iteration)))))
(define (asn1-object->pbe-parameter asn1-object)
  (der-sequence->simple-asn1-encodable asn1-object make-pbe-parameter))
(define/typed (pbe-parameter:salt (pbe-parameter pbe-parameter?))
  (der-octet-string-value (pbe-parameter-salt pbe-parameter)))
(define/typed (pbe-parameter:iteration (pbe-parameter pbe-parameter?))
  (der-integer-value (pbe-parameter-iteration pbe-parameter)))

;; PBES2-params ::= SEQUENCE {
;;     keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
;;     encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
;; }
;;
;; PBES2-KDFs ALGORITHM-IDENTIFIER ::=
;;     { {PBKDF2-params IDENTIFIED BY id-PBKDF2}, ... }
;;
;; PBES2-Encs ALGORITHM-IDENTIFIER ::= { ... }
;; 
;; PBKDF2-params ::= SEQUENCE {
;;     salt CHOICE {
;;         specified OCTET STRING,
;;         otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
;;     },
;;     iterationCount INTEGER (1..MAX),
;;     keyLength INTEGER (1..MAX) OPTIONAL,
;;     prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT
;;     algid-hmacWithSHA1 }
(define-record-type pbes2-parameter
  (parent <asn1-encodable-object>)
  (fields key-derivation encryption-scheme)
  (protocol (lambda (n)
	      (lambda/typed ((key-derivation algorithm-identifier?)
			     (encryption-scheme algorithm-identifier?))
	       ((n simple-asn1-encodable-object->der-sequence)
		key-derivation encryption-scheme)))))

(define/typed (asn1-object->pbes2-parameter (asn1-object der-sequence?))
  (let ((aids (map asn1-object->algorithm-identifier
		(asn1-collection-elements asn1-object))))
    (unless (= (length aids) 2)
      (springkussen-assertion-violation 'asn1-object->pbes2-parameter
					"Invalid format"))
    (make-pbes2-parameter
     (make-algorithm-identifier (algorithm-identifier-algorithm (car aids))
				(asn1-object->pbkdf2-parameters
				 (algorithm-identifier-parameters (car aids))))
     (cadr aids))))
;; prf != OPTIONAL for us
(define-record-type pbkdf2-parameters
  (parent <asn1-encodable-object>)
  (fields salt iteration key-length prf)
  (protocol (lambda (n)
	      (case-lambda/typed
	       (((salt der-octet-string?)
		 (iteration der-integer?)
		 (prf algorithm-identifier?))
		((n simple-asn1-encodable-object->der-sequence)
		 salt iteration #f prf))
	       (((salt der-octet-string?)
		 (iteration der-integer?)
		 (key-length der-integer?)
		 (prf algorithm-identifier?))
		((n simple-asn1-encodable-object->der-sequence)
		 salt iteration key-length prf))))))
(define/typed (asn1-object->pbkdf2-parameters (asn1-object der-sequence?))
  (let ((e (asn1-collection-elements asn1-object)))
    (case (length e)
      ((3)
       (make-pbkdf2-parameters (car e) (cadr e)
			       (asn1-object->algorithm-identifier (caddr e))))
      ((4)
       (make-pbkdf2-parameters (car e) (cadr e) (caddr e)
			       (asn1-object->algorithm-identifier (cadddr e))))
      (else
       (springkussen-error 'asn1-object->pbkdf2-parameters
			   "Unsported format" asn1-object)))))
		  

(define/typed (pbes2-parameter->pbe-cipher&parameter
	       (parameter pbes2-parameter?))
  (define key-derivation (pbes2-parameter-key-derivation parameter))
  (define (scheme&parameter parameter)
    (define aid (pbes2-parameter-encryption-scheme parameter))
    (define (get-scheme oid)
      (cond ((assoc oid *enc-oids*) => cdr)
	    (else (springkussen-error
		   'pbes2-parameter->pbe-cipher&parameter
		   "Unsupported encryption" oid))))
    (define (get-param scheme param)
      ((cond ((assoc scheme *cipher-parameter*) => cdr)
	    (else (springkussen-error
		   'pbes2-parameter->pbe-cipher&parameter
		   "Unsupported encryption" scheme))) param))
    (let ((enc (get-scheme (der-object-identifier-value
			       (algorithm-identifier-algorithm aid)))))
      (values enc (get-param enc (algorithm-identifier-parameters aid)))))
  (define (parse-key-derivation param)
    (define (get-prf-digest aid)
      (define oid (der-object-identifier-value
		   (algorithm-identifier-algorithm aid)))
      (cond ((assoc oid *prf-oids*) => cdr)
	    (else (springkussen-error 'pbes2-parameter->pbe-cipher&parameter
				      "Unsupported PRF" oid))))
    (unless (pbkdf2-parameters? param)
      (springkussen-error 'pbes2-parameter->pbe-cipher&parameter
			  "Invalid parameter format"))
    (values (der-octet-string-value (pbkdf2-parameters-salt param))
	    (der-integer-value (pbkdf2-parameters-iteration param))
	    (cond ((pbkdf2-parameters-key-length param) => der-integer-value)
		  (else #f))
	    (get-prf-digest (pbkdf2-parameters-prf param))))
  (let ((kdf-oid (der-object-identifier-value
		  (algorithm-identifier-algorithm key-derivation)))
	(param (algorithm-identifier-parameters key-derivation)))
    (unless (string=? "1.2.840.113549.1.5.12" kdf-oid)
      (springkussen-assertion-violation 'pbes2-parameter->pbe-cipher
					"Only PBKDF2 is supported" kdf-oid))
    (let-values (((scheme cipher-param) (scheme&parameter parameter))
		 ((salt iteration key-length md) (parse-key-derivation param)))
      (values (make-pbe-cipher pbes2-scheme-descriptor
	       (make-pbe-cipher-encryption-scheme-parameter scheme))
	      (make-cipher-parameter
	       cipher-param
	       (make-pbes2-cipher-encryption-mode-parameter *mode:cbc*)
	       (make-pbe-cipher-salt-parameter salt)
	       (make-pbe-cipher-iteration-parameter iteration)
	       (make-pbe-cipher-key-size-parameter key-length)
	       (make-pbe-cipher-kdf-parameter
		(make-pbkdf-2
		 (make-pbe-kdf-prf-parameter
		  (mac->pbkdf2-prf *mac:hmac*
				   (make-partial-hmac-parameter md))))))))))

(define *enc-oids*
  `(
    ("2.16.840.1.101.3.4.1.2"  . ,*scheme:aes-128*) ;; AES128-CBC-Pad
    ("2.16.840.1.101.3.4.1.22" . ,*scheme:aes-192*) ;; AES192-CBC-Pad
    ("2.16.840.1.101.3.4.1.42" . ,*scheme:aes-256*) ;; AES256-CBC-Pad
    ("1.2.840.113549.3.2"      . ,*scheme:rc2*)	    ;; RC2-CBC-Pad
    ("1.2.840.113549.3.9"      . ,*scheme:rc5*)	    ;; RC5-CBC-Pad
    ("1.3.14.3.2.7"            . ,*scheme:des*)	    ;; DES-CBC-Pad
    ("1.2.840.113549.3.7"      . ,*scheme:desede*)  ;; DES-EDE3-CBC-Pad
    ))

(define (->rc2-cbc-parameter iv key-length)
  (define bits (* key-length 8))
  (der-sequence
   (make-der-integer (case bits
		       ((40) 160)
		       ((64) 120)
		       ((128) 58)
		       (else bits)))
   (make-der-octet-string iv)))
(define (->rc5-cbc-parameter iv key-length)
  (der-sequence
   (make-der-integer 16)
   ;; TODO maybe we should care about this?
   (make-der-integer 12)
   (make-der-integer 64) ;; we don't support 128 bit RC5
   (make-der-octet-string iv)))
(define (->iv-parameter iv key-length) (make-der-octet-string iv))
(define *enc-parameter*
  `(
    (,*scheme:rc2*     . ,->rc2-cbc-parameter)
    (,*scheme:rc5*     . ,->rc5-cbc-parameter)
    (,*scheme:aes-128* . ,->iv-parameter)
    (,*scheme:aes-192* . ,->iv-parameter)
    (,*scheme:aes-256* . ,->iv-parameter)
    (,*scheme:des*     . ,->iv-parameter)
    (,*scheme:desede*  . ,->iv-parameter)
    ))

(define (->rc2-cbc-cipher-parameter param)
  (unless (der-sequence? param)
    (springkussen-assertion-violation '->rc2-cbc-cipher-parameter
				      "Unknown param" param))
  (let-values (((version iv) (apply values (asn1-collection-elements param))))
    (let ((v (der-integer-value version)))
      (make-cipher-parameter
       (make-pbe-cipher-key-size-parameter (case v
					     ((160) 5)
					     ((120) 8)
					     ((58) 16)
					     (else (div v 8))))
       (make-iv-paramater (der-octet-string-value iv))))))

(define (->rc5-cbc-cipher-parameter param)
  (unless (der-sequence? param)
    (springkussen-assertion-violation '->rc2-cbc-cipher-parameter
				      "Unknown param" param))
  (let-values (((version round block-size iv)
		(apply values (asn1-collection-elements param))))
    (make-cipher-parameter
     (make-iv-paramater (der-octet-string-value iv))
     (make-round-parameter (der-integer-value round)))))
  
(define (->iv-cipher-parameter param)
  (make-iv-paramater (der-octet-string-value param)))
(define *cipher-parameter*
  `(
    (,*scheme:rc2*     . ,->rc2-cbc-cipher-parameter)
    (,*scheme:rc5*     . ,->rc5-cbc-cipher-parameter)
    (,*scheme:aes-128* . ,->iv-cipher-parameter)
    (,*scheme:aes-192* . ,->iv-cipher-parameter)
    (,*scheme:aes-256* . ,->iv-cipher-parameter)
    (,*scheme:des*     . ,->iv-cipher-parameter)
    (,*scheme:desede*  . ,->iv-cipher-parameter)
    ))
    

(define *reverse-enc-oids* (map (lambda (e) (cons (cdr e) (car e))) *enc-oids*))
(define (make-pbes2-encryption-scheme scheme iv key-length)
  (make-algorithm-identifier
   (make-der-object-identifier
    (cond ((assq scheme *reverse-enc-oids*) => cdr)
	  (else (springkussen-assertion-violation 'make-pbes2-encryption-scheme
						  "Unknown scheme" scheme))))
   (cond ((assq scheme *enc-parameter*) =>
	  (lambda (s) ((cdr s) iv key-length)))
	 (else (springkussen-assertion-violation 'make-pbes2-encryption-scheme
						  "Unknown scheme" scheme)))))

(define *prf-oids*
  `(("1.2.840.113549.2.7"  . ,*digest:sha1*)
    ("1.2.840.113549.2.8"  . ,*digest:sha224*)
    ("1.2.840.113549.2.9"  . ,*digest:sha256*)
    ("1.2.840.113549.2.10" . ,*digest:sha384*)
    ("1.2.840.113549.2.11" . ,*digest:sha512*)
    ("1.2.840.113549.2.12" . ,*digest:sha512/224*)
    ("1.2.840.113549.2.13" . ,*digest:sha512/256*)))
(define *reverse-prf-oids* (map (lambda (e) (cons (cdr e) (car e))) *prf-oids*))
(define (make-pbes2-kdf-parameter salt iteration key-length md)
  (make-algorithm-identifier
   (make-der-object-identifier "1.2.840.113549.1.5.12")
   (make-pbkdf2-parameters
    (make-der-octet-string salt)
    (make-der-integer iteration)
    (make-der-integer key-length)
    (make-algorithm-identifier
     (make-der-object-identifier
      (cond ((assq md *reverse-prf-oids*) => cdr)
	    (else (springkussen-assertion-violation
		   'make-pbes2-kdf-parameter "Unknown digest" md))))))))
     

)

