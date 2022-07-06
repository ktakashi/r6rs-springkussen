;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/asymmetric.sls - Asymmetric cipher APIs
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
(library (springkussen cipher asymmetric)
    (export asymmetric-cipher-spec?
	    asymmetric-cipher-spec-builder

	    asymmetric-cipher? make-asymmetric-cipher
	    asymmetric-cipher:encrypt-bytevector
	    asymmetric-cipher:decrypt-bytevector
	    
	    asymmetric-key?
	    
	    ;; Scheme descriptors
	    asymmetric-scheme-descriptor?
	    asymmetric-scheme-descriptor-name

	    key-pair-factory?
	    key-pair-factory:generate-key-pair

	    key-pair? key-pair-private key-pair-public
	    private-key? public-key?
	    
	    ;; descriptors
	    (rename (rsa-descriptor *scheme:rsa*))
	    ;; key factories
	    (rename (*rsa-key-factory* *key-factory:rsa*)
		    (*rsa-key-pair-factory* *key-pair-factory:rsa*))
	    rsa-key-parameter?
	    make-rsa-public-key-parameter rsa-public-key-parameter?
	    make-rsa-private-key-parameter rsa-private-key-parameter?
	    make-rsa-crt-private-key-parameter rsa-crt-private-key-parameter?
	    make-random-generator-key-parameter random-generator-key-parameter?
	    make-key-size-key-parameter key-size-key-parameter?
	    make-public-exponent-key-parameter public-exponent-key-parameter?
	    
	    pkcs1-v1.5-encoding oaep-encoding

	    make-cipher-parameter cipher-parameter?
	    random-generator-encoding-parameter?
	    make-random-generator-encoding-parameter
	    make-digest-encoding-parameter digest-encoding-parameter?
	    make-mgf-digest-encoding-parameter mgf-digest-encoding-parameter?
	    make-mgf-encoding-parameter mgf-encoding-parameter?
	    make-label-encoding-parameter label-encoding-parameter?
	    )
    (import (rnrs)
	    (springkussen cipher parameter) ;; for convenience
	    (springkussen cipher asymmetric scheme rsa)
	    (springkussen cipher asymmetric scheme descriptor)
	    (springkussen cipher asymmetric key)
	    (springkussen cipher asymmetric encoding)
	    (springkussen conditions)
	    (springkussen misc record))

(define-record-type asymmetric-cipher-spec
  (fields scheme encoding))

(define (check-type type pred)
  (lambda (v)
    (unless (pred v)
      (springkussen-assertion-violation 'asymmetric-cipher-spec-builder
					(string-append type " is required")
					v))
    v))


(define-syntax asymmetric-cipher-spec-builder
  (make-record-builder asymmetric-cipher-spec
   ((scheme #f (check-type "scheme" asymmetric-scheme-descriptor?))
    ;; For now, we are *new* application, so should use OAEP :D
    (encoding pkcs1-v1.5-encoding))))

(define-record-type (asymmetric-cipher %make asymmetric-cipher?)
  (fields cipher-spec
	  state-key
	  encoder
	  decoder))

(define make-asymmetric-cipher
  (case-lambda
   ((cipher-spec asymmetric-key)
    (make-asymmetric-cipher cipher-spec asymmetric-key #f))
   ((cipher-spec asymmetric-key param)
    (unless (asymmetric-cipher-spec? cipher-spec)
      (springkussen-assertion-violation 'make-asymmetric-cipher
       "Asymmetric cipher spec is required" cipher-spec))
    (unless (asymmetric-key? asymmetric-key)
      (springkussen-assertion-violation 'make-asymmetric-cipher
					"Asymmetric key is required"))
    (let* ((scheme (asymmetric-cipher-spec-scheme cipher-spec))
	   (state-key (asymmetric-scheme-descriptor:start
		       scheme asymmetric-key param)))
      (let-values (((encoder decoder)
		    ((asymmetric-cipher-spec-encoding cipher-spec)
		     scheme param)))
	(%make cipher-spec state-key encoder decoder))))))

(define (asymmetric-cipher:encrypt-bytevector cipher bv)
  (unless (asymmetric-cipher? cipher)
    (springkussen-assertion-violation 'asymmetric-cipher:encrypt-bytevector
				      "Asymmetric cipher is required" cipher))
  (unless (bytevector? bv)
    (springkussen-assertion-violation 'asymmetric-cipher:encrypt-bytevector
				      "Bytevector is required" bv))
  (let* ((encoder (asymmetric-cipher-encoder cipher))
	 (spec (asymmetric-cipher-cipher-spec cipher))
	 (scheme (asymmetric-cipher-spec-scheme spec))
	 (state-key (asymmetric-cipher-state-key cipher))
	 (encoded (or (and encoder (encoder bv state-key)) bv))
	 (r (asymmetric-scheme-descriptor:encrypt scheme state-key encoded)))
    (asymmetric-scheme-descriptor:done scheme state-key)
    r))

(define (asymmetric-cipher:decrypt-bytevector cipher bv)
  (unless (asymmetric-cipher? cipher)
    (springkussen-assertion-violation 'asymmetric-cipher:decrypt-bytevector
				      "Asymmetric cipher is required" cipher))
  (unless (bytevector? bv)
    (springkussen-assertion-violation 'asymmetric-cipher:decrypt-bytevector
				      "Bytevector is required" bv))
  (let* ((decoder (asymmetric-cipher-decoder cipher))
	 (spec (asymmetric-cipher-cipher-spec cipher))
	 (scheme (asymmetric-cipher-spec-scheme spec))
	 (state-key (asymmetric-cipher-state-key cipher))
	 (pt (asymmetric-scheme-descriptor:decrypt scheme state-key bv))
	 (r (or (and decoder (decoder pt state-key)) pt)))
    (asymmetric-scheme-descriptor:done scheme state-key)
    r))

)
