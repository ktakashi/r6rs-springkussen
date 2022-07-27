;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/signature.sls - Signer/Verifier APIs
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
(library (springkussen signature)
    (export signer? make-signer
	    signer:sign-message
	    signer:init!
	    signer:process!
	    signer:sign

	    verifier? make-verifier
	    verifier:verify-signature
	    verifier:init!
	    verifier:process!
	    verifier:verify
	    
	    signer-descriptor?
	    signer-descriptor-name

	    verifier-descriptor?
	    verifier-descriptor-name
	    
	    signature-parameter? make-signature-parameter
	    make-signature-digest-parameter signature-digest-parameter?
	    
	    ;; re-export (for convenience)
	    asymmetric-key?
	    asymmetric-key:import-key
	    asymmetric-key:export-key
	    asymmetric-key-operation?

	    signature:export-asymmetric-key
	    
	    key-pair? key-pair-private key-pair-public
	    private-key? public-key?
	    
	    ;; RSA
	    rsa-private-key? rsa-public-key?
	    (rename (rsa-signer-descriptor *signer:rsa*)
		    (rsa-verifier-descriptor *verifier:rsa*))
	    make-rsa-signature-encode-parameter rsa-signature-encode-parameter?
	    pkcs1-emsa-v1.5-encode pkcs1-emsa-pss-encode
	    
	    make-rsa-signature-verify-parameter rsa-signature-verify-parameter?
	    pkcs1-emsa-v1.5-verify pkcs1-emsa-pss-verify

	    make-rsa-signature-mgf-digest-parameter
	    rsa-signature-mgf-digest-parameter?
	    ;; in case MGF-2 or custom MGF is there
	    make-rsa-signature-mgf-parameter rsa-signature-mgf-parameter?
	    make-rsa-signature-salt-parameter rsa-signature-salt-parameter?
	    make-rsa-signature-salt-length-parameter
	    rsa-signature-salt-length-parameter?

	    ;; ECDSA
	    (rename (ecdsa-signer-descriptor *signer:ecdsa*)
		    (ecdsa-verifier-descriptor *verifier:ecdsa*))

	    ;; Key factories (re-export for convenience)
	    key-factory?
	    key-factory:generate-key
	    key-pair-factory?
	    key-pair-factory:generate-key-pair
	    
	    *key-factory:rsa*	   ;; re-export
	    *key-pair-factory:rsa* ;; re-export
	    *public-key-operation:rsa*
	    *private-key-operation:rsa*

	    key-parameter? make-key-parameter
	    make-rsa-public-key-parameter rsa-public-key-parameter?
	    make-rsa-private-key-parameter rsa-private-key-parameter?
	    make-rsa-crt-private-key-parameter rsa-crt-private-key-parameter?
	    make-random-generator-key-parameter random-generator-key-parameter?
	    make-key-size-key-parameter key-size-key-parameter?
	    make-public-exponent-key-parameter public-exponent-key-parameter?
	    
	    (rename (*ecdsa-key-factory* *key-factory:ecdsa*)
		    (*ecdsa-key-pair-factory* *key-pair-factory:ecdsa*)
		    (*ecdsa-private-key-operation*
		     *private-key-operation:ecdsa*)
		    (*ecdsa-public-key-operation*
		     *public-key-operation:ecdsa*))

	    make-random-k-generator

	    ecdsa-private-key?
	    ecdsa-public-key?

	    ecdsa-signature-encode-type
	    make-ecdsa-encode-parameter ecdsa-encode-parameter?
	    make-ecdsa-ec-parameter ecdsa-ec-parameter?
	    make-ecdsa-public-key-parameter ecdsa-public-key-parameter?
	    make-ecdsa-private-key-parameter ecdsa-private-key-parameter?

	    ;; EC parameters
	    ec-parameter?
	    (rename (NIST-P-192 *ec-parameter:p192*)
		    (NIST-P-224 *ec-parameter:p224*)
		    (NIST-P-256 *ec-parameter:p256*)
		    (NIST-P-384 *ec-parameter:p384*)
		    (NIST-P-521 *ec-parameter:p521*)
		    (NIST-K-163 *ec-parameter:k163*)
		    (NIST-K-233 *ec-parameter:k233*)
		    (NIST-K-283 *ec-parameter:k283*)
		    (NIST-K-409 *ec-parameter:k409*)
		    (NIST-K-571 *ec-parameter:k571*)
		    (NIST-B-163 *ec-parameter:b163*)
		    (NIST-B-233 *ec-parameter:b233*)
		    (NIST-B-283 *ec-parameter:b283*)
		    (NIST-B-409 *ec-parameter:b409*)
		    (NIST-B-571 *ec-parameter:b571*)
		    (secp192r1 *ec-parameter:secp192r1*)
		    (secp224r1 *ec-parameter:secp224r1*)
		    (secp256r1 *ec-parameter:secp256r1*)
		    (secp384r1 *ec-parameter:secp384r1*)
		    (secp521r1 *ec-parameter:secp521r1*)
		    (sect163k1 *ec-parameter:sect163k1*)
		    (sect233k1 *ec-parameter:sect233k1*)
		    (sect283k1 *ec-parameter:sect283k1*)
		    (sect409k1 *ec-parameter:sect409k1*)
		    (sect571k1 *ec-parameter:sect571k1*)
		    (sect163r2 *ec-parameter:sect163r2*)
		    (sect233r1 *ec-parameter:sect233r1*)
		    (sect283r1 *ec-parameter:sect283r1*)
		    (sect409r1 *ec-parameter:sect409r1*)		    
		    (sect571r1 *ec-parameter:sect571r1*)
		    (secp192k1 *ec-parameter:secp192k1*)
		    (secp224k1 *ec-parameter:secp224k1*)
		    (secp256k1 *ec-parameter:secp256k1*)
		    (sect163r1 *ec-parameter:sect163r1*)
		    (sect239k1 *ec-parameter:sect239k1*)
		    (sect113r1 *ec-parameter:sect113r1*)))
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen cipher key)
	    (springkussen cipher asymmetric)
	    (springkussen signature descriptor)
	    (springkussen signature parameters)
	    (springkussen signature rsa)
	    (springkussen signature ecdsa))

;; utility
;; Import should also be possible by checking the 
;; ASN1 structure, but that's a bit more trouble, so we don't do, yet
(define (signature:export-asymmetric-key key)
  (define key-operation 
    (cond ((rsa-public-key? key) *public-key-operation:rsa*)
	  ((rsa-private-key? key) *private-key-operation:rsa*)
	  ((ecdsa-public-key? key) *ecdsa-public-key-operation*)
	  ((ecdsa-private-key? key) *ecdsa-private-key-operation*)
	  (else (springkussen-assertion-violation 'signature:export-key
						  "Unknown key" key))))
  (asymmetric-key:export-key key-operation key))



(define (signer:sign-message signer message)
  (signer:init! signer)
  (signer:process! signer message)
  (signer:sign signer))

(define (verifier:verify-signature verifier message signature)
  (verifier:init! verifier)
  (verifier:process! verifier message)
  (verifier:verify verifier signature))

(define-record-type signature
  (fields (mutable state)
	  descriptor
	  key
	  parameter))

(define-syntax define-signature:process!
  (syntax-rules ()
    ((_ name pred process!)
     (define name
       (case-lambda
	((sig bv) (name sig bv 0))
	((sig bv s) (name sig bv s (bytevector-length bv)))
	((sig bv s e)
	 (unless (pred sig)
	   (springkussen-assertion-violation 'name
					     "Wrong type of argument" sig))
	 (process! (signature-descriptor sig) (signature-state sig) bv s e)
	 sig))))))

(define-record-type signer
  (parent signature)
  (protocol (lambda (n)
	      (define (check key descriptor)
		(unless (private-key? key)
		  (springkussen-assertion-violation 'make-signer
						    "Private key required"))
		(unless (signer-descriptor? descriptor)
		  (springkussen-assertion-violation 'make-signer
						    "Signer descriptor required"
						    descriptor)))
	      (case-lambda
	       ((descriptor key)
		(check key descriptor)
		((n #f descriptor key #f)))
	       ((descriptor key parameter)
		(check key descriptor)
		(unless (signature-parameter? parameter)
		  (springkussen-assertion-violation 'make-signer
		    "Parameter must be signature parameter" parameter))
		((n #f descriptor key parameter)))))))
		

(define (signer:init! signer)
  (unless (signer? signer)
    (springkussen-assertion-violation 'signer:init! "Signer required" signer))
  (let ((st (signer-descriptor:init (signature-descriptor signer)
				    (signature-key signer)
				    (signature-parameter signer))))
    (signature-state-set! signer st)
    signer))

(define-signature:process! signer:process! signer? signer-descriptor:process!)

(define (signer:sign signer)
  (signer-descriptor:sign (signature-descriptor signer)
			  (signature-state signer)))

(define-record-type verifier
  (parent signature)
  (protocol (lambda (n)
	      (define (check key descriptor)
		(unless (public-key? key)
		  (springkussen-assertion-violation 'make-verifier
						    "Public key required"))
		(unless (verifier-descriptor? descriptor)
		  (springkussen-assertion-violation 'make-verifier
		    "Verifier descriptor required" descriptor)))
	      (case-lambda
	       ((descriptor key)
		(check key descriptor)
		((n #f descriptor key #f)))
	       ((descriptor key parameter)
		(check key descriptor)
		(unless (signature-parameter? parameter)
		  (springkussen-assertion-violation 'make-verifier
		    "Parameter must be signature parameter" parameter))
		((n #f descriptor key parameter)))))))

(define (verifier:init! verifier)
  (unless (verifier? verifier)
    (springkussen-assertion-violation 'verifier:init!
				      "Verifier required" verifier))
  (let ((st (verifier-descriptor:init (signature-descriptor verifier)
				      (signature-key verifier)
				      (signature-parameter verifier))))
    (signature-state-set! verifier st)
    verifier))

(define-signature:process! verifier:process! verifier?
  verifier-descriptor:process!)

(define (verifier:verify verifier signature)
  (verifier-descriptor:verify (signature-descriptor verifier)
			      (signature-state verifier)
			      signature))

)
