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
	    pbes2-parameter? make-pbes2-parameter asn1-object->pbes2-parameter
	    make-pbes2-encryption-scheme
	    make-pbes2-kdf-parameter
	    
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


;; PBES2-params ::= SEQUENCE {
;;     keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
;;     encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
;; }
;;
;; PBES2-KDFs ALGORITHM-IDENTIFIER ::=
;;     { {PBKDF2-params IDENTIFIED BY id-PBKDF2}, ... }
;;
;;   PBES2-Encs ALGORITHM-IDENTIFIER ::= { ... }
(define-record-type pbes2-parameter
  (parent <asn1-encodable-object>)
  (fields key-derivation encryption-scheme)
  (protocol (lambda (n)
	      (lambda/typed ((key-derivation algorithm-identifier?)
			     (encryption-scheme algorithm-identifier?))
	       ((n simple-asn1-encodable-object->der-sequence)
		key-derivation encryption-scheme)))))
(define/typed (asn1-object->pbes2-parameter (asn1-object der-sequence?))
  (apply make-pbes2-parameter
	 (map asn1-object->algorithm-identifier
	      (asn1-collection-elements asn1-object))))

(define *enc-oids*
  `(
    ("2.16.840.1.101.3.4.1.2" .  ,*scheme:aes-128*) ;; AES128-CBC-Pad
    ("2.16.840.1.101.3.4.1.22" . ,*scheme:aes-192*) ;; AES192-CBC-Pad
    ("2.16.840.1.101.3.4.1.42" . ,*scheme:aes-256*) ;; AES256-CBC-Pad
    ))
(define *reverse-enc-oids* (map (lambda (e) (cons (cdr e) (car e))) *enc-oids*))
(define (make-pbes2-encryption-scheme scheme iv)
  (make-algorithm-identifier
   (make-der-object-identifier
    (cond ((assq scheme *reverse-enc-oids*) => cdr)
	  (else (springkussen-assertion-violation 'make-pbes2-encryption-scheme
						  "Unknown scheme" scheme))))
   (make-der-octet-string iv)))

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
   (der-sequence
    (make-der-octet-string salt)
    (make-der-integer iteration)
    (make-der-integer key-length)
    (make-algorithm-identifier
     (cond ((assq md *reverse-prf-oids*) => cdr)
	   (else (springkussen-assertion-violation
		  'make-pbes2-kdf-parameter "Unknown digest" md)))))))
     

)

