;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/symmetric.sls - Symmetric cipher APIs
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
(library (springkussen cipher symmetric)
    (export symmetric-cipher-spec?
	    symmetric-cipher-spec-builder

	    symmetric-cipher? make-symmetric-cipher
	    symmetric-cipher:encrypt-bytevector
	    symmetric-cipher:decrypt-bytevector
	    
	    symmetric-key? make-symmetric-key
	    
	    ;; Scheme descriptors
	    symmetric-scheme-descriptor?
	    (rename (aes-descriptor     *scheme:aes*)
		    (aes-128-descriptor *scheme:aes-128*)
		    (aes-192-descriptor *scheme:aes-192*)
		    (aes-256-descriptor *scheme:aes-256*)
		    (des-descriptor     *scheme:des*)
		    (desede-descriptor  *scheme:desede*)
		    (rc5-descriptor     *scheme:rc5*))

	    ;; Mode descriptors
	    symmetric-mode-descriptor?
	    (rename (ecb-mode-descriptor *mode:ecb*)
		    (cbc-mode-descriptor *mode:cbc*))

	    ;; Mode parameters
	    mode-parameter?
	    (rename (make-composite-parameter make-mode-parameter))
	    make-iv-paramater iv-parameter?
	    make-counter-parameter counter-parameter?
	    make-rfc3686-parameter rfc3686-parameter?
	    make-round-parameter round-parameter?
	    
	    pkcs7-padding
	    )
    (import (rnrs)
	    (springkussen cipher symmetric scheme aes)
	    (springkussen cipher symmetric scheme des)
	    (springkussen cipher symmetric scheme rc5)
	    (springkussen cipher symmetric scheme descriptor)
	    (springkussen cipher symmetric mode ecb)
	    (springkussen cipher symmetric mode cbc)
	    (springkussen cipher symmetric mode descriptor)
	    (springkussen cipher symmetric mode parameter)
	    (springkussen cipher symmetric key)
	    (springkussen conditions)
	    (springkussen misc record))

(define-record-type symmetric-cipher-spec
  (fields scheme mode padding))

(define (check-type type pred)
  (lambda (v)
    (unless (pred v)
      (springkussen-assertion-violation 'symmetric-cipher-spec-builder
					(string-append type " is required")
					v))
    v))

(define-syntax symmetric-cipher-spec-builder
  (make-record-builder symmetric-cipher-spec
   ((scheme #f (check-type "Encryption scheme" symmetric-scheme-descriptor?))
    (mode #f (check-type "Encryption mode" symmetric-mode-descriptor?))
    (padding pkcs7-padding))))

(define-record-type (symmetric-cipher %make-symmetric-cipher symmetric-cipher?)
  (fields cipher-spec
	  mode-key
	  padder
	  unpadder))

(define make-symmetric-cipher
  (case-lambda
   ((cipher-spec symmetric-key)
    (make-symmetric-cipher cipher-spec symmetric-key #f))
   ((cipher-spec symmetric-key param)
    (unless (symmetric-cipher-spec? cipher-spec)
      (springkussen-assertion-violation 'make-symmetric-cipher
       "Symmetric cipher spec is required" cipher-spec))
    (unless (symmetric-key? symmetric-key)
      (springkussen-assertion-violation 'make-symmetric-cipher
					"Symmetric key is required"))
    (let* ((scheme (symmetric-cipher-spec-scheme cipher-spec))
	   (mode (symmetric-cipher-spec-mode cipher-spec))
	   (mode-key (symmetric-mode-descriptor:start
		      mode scheme (symmetric-key-raw-value symmetric-key)
		      param)))
      (let-values (((padder unpadder)
		    ((symmetric-cipher-spec-padding cipher-spec))))
	(%make-symmetric-cipher cipher-spec mode-key padder unpadder))))))

(define (symmetric-cipher:encrypt-bytevector cipher bv)
  (unless (symmetric-cipher? cipher)
    (springkussen-assertion-violation 'symmetric-cipher:encrypt-bytevector
				      "Symmetric cipher is required" cipher))
  (unless (bytevector? bv)
    (springkussen-assertion-violation 'symmetric-cipher:encrypt-bytevector
				      "Bytevector is required" bv))
  (let* ((padder (symmetric-cipher-padder cipher))
	 (spec (symmetric-cipher-cipher-spec cipher))
	 (mode (symmetric-cipher-spec-mode spec))
	 (scheme (symmetric-cipher-spec-scheme spec))
	 (block-len (symmetric-scheme-descriptor-block-size scheme))
	 (mode-key (symmetric-cipher-mode-key cipher))
	 (padded (or (and padder (padder bv block-len)) bv))
	 (r (symmetric-mode-descriptor:encrypt mode mode-key padded)))
      (symmetric-mode-descriptor:done mode mode-key)
      r))

(define (symmetric-cipher:decrypt-bytevector cipher bv)
  (unless (symmetric-cipher? cipher)
    (springkussen-assertion-violation 'symmetric-cipher:decrypt-bytevector
				      "Symmetric cipher is required" cipher))
  (unless (bytevector? bv)
    (springkussen-assertion-violation 'symmetric-cipher:decrypt-bytevector
				      "Bytevector is required" bv))
  (let* ((unpadder (symmetric-cipher-unpadder cipher))
	 (spec (symmetric-cipher-cipher-spec cipher))
	 (mode (symmetric-cipher-spec-mode spec))
	 (scheme (symmetric-cipher-spec-scheme spec))
	 (block-len (symmetric-scheme-descriptor-block-size scheme))
	 (mode-key (symmetric-cipher-mode-key cipher))
	 (r (symmetric-mode-descriptor:decrypt mode mode-key bv)))
      (symmetric-mode-descriptor:done mode mode-key)
      (or (and unpadder (unpadder r block-len)) r)))

(define (pkcs7-padding)
  (define (pad bv block-size)
    (let* ((len (bytevector-length bv))
	   (mod (mod len block-size))
	   (t (- block-size mod))
	   (padding (if (zero? t) block-size t)))
      (let ((new (make-bytevector (+ len padding) padding)))
	(bytevector-copy! bv 0 new 0 len)
	new)))
  (define (unpad bv block-size)
    (let* ((len (bytevector-length bv))
	   (pad (bytevector-u8-ref bv (- len 1)))
	   (new (make-bytevector (- len pad) 0)))
      (bytevector-copy! bv 0 new 0 (- len pad))
      new))
  (values pad unpad))


)
