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

	    symmetric-cipher-operation
	    symmetric-cipher:init!
	    symmetric-cipher:encrypt!
	    symmetric-cipher:encrypt-last-block!
	    symmetric-cipher:decrypt!
	    symmetric-cipher:decrypt-last-block!
	    symmetric-cipher:done!
	    
	    symmetric-key? make-symmetric-key
	    
	    ;; Scheme descriptors
	    symmetric-scheme-descriptor?
	    symmetric-scheme-descriptor-name
	    symmetric-scheme-descriptor-block-size
	    (rename (aes-descriptor     *scheme:aes*)
		    (aes-128-descriptor *scheme:aes-128*)
		    (aes-192-descriptor *scheme:aes-192*)
		    (aes-256-descriptor *scheme:aes-256*)
		    (des-descriptor     *scheme:des*)
		    (desede-descriptor  *scheme:desede*)
		    (rc2-descriptor     *scheme:rc2*)
		    (rc5-descriptor     *scheme:rc5*))

	    ;; Mode descriptors
	    symmetric-mode-descriptor?
	    symmetric-mode-descriptor-name
	    (rename (ecb-mode-descriptor *mode:ecb*)
		    (cbc-mode-descriptor *mode:cbc*))

	    make-cipher-parameter cipher-parameter?
	    ;; Mode parameters
	    mode-parameter? 
	    make-iv-paramater iv-parameter?
	    make-counter-parameter counter-parameter?
	    make-rfc3686-parameter rfc3686-parameter?
	    make-round-parameter round-parameter?
	    
	    pkcs7-padding
	    )
    (import (rnrs)
	    (springkussen cipher parameter) ;; for convenience
	    (springkussen cipher symmetric scheme aes)
	    (springkussen cipher symmetric scheme des)
	    (springkussen cipher symmetric scheme rc2)
	    (springkussen cipher symmetric scheme rc5)
	    (springkussen cipher symmetric scheme descriptor)
	    (springkussen cipher symmetric mode ecb)
	    (springkussen cipher symmetric mode cbc)
	    (springkussen cipher symmetric mode descriptor)
	    (springkussen cipher symmetric mode parameter)
	    (springkussen cipher symmetric key)
	    (springkussen conditions)
	    (springkussen misc record)
	    (springkussen misc bytevectors))

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

(define-enumeration symmetric-cipher-operation (encrypt decrypt)
  symmetric-cipher-operations)

(define-record-type (symmetric-cipher %make-symmetric-cipher symmetric-cipher?)
  (fields cipher-spec
	  (mutable op)
	  (mutable mode-key)
	  padder
	  unpadder))

(define (make-symmetric-cipher cipher-spec)
  (unless (symmetric-cipher-spec? cipher-spec)
    (springkussen-assertion-violation 'make-symmetric-cipher
      "Symmetric cipher spec is required" cipher-spec))
  (let-values (((padder unpadder)
		((symmetric-cipher-spec-padding cipher-spec))))
    (%make-symmetric-cipher cipher-spec #f #f padder unpadder)))

(define symmetric-cipher:encrypt-bytevector
  (case-lambda
   ((cipher symmetric-key bv)
    (symmetric-cipher:encrypt-bytevector cipher symmetric-key #f bv))
   ((cipher symmetric-key param bv)
    (unless (symmetric-cipher? cipher)
      (springkussen-assertion-violation 'symmetric-cipher:encrypt-bytevector
					"Symmetric cipher is required" cipher))
    (unless (symmetric-key? symmetric-key)
      (springkussen-assertion-violation 'symmetric-cipher:encrypt-bytevector
					"Symmetric key is required"))
    (unless (or (not param) (cipher-parameter? param))
      (springkussen-assertion-violation 'symmetric-cipher:encrypt-bytevector
					"Cipher parameter or #f  is required"))
    (unless (bytevector? bv)
      (springkussen-assertion-violation 'symmetric-cipher:encrypt-bytevector
					"Bytevector is required" bv))
    (let* ((block-size (symmetric-cipher:block-size cipher))
	   (pt-len (bytevector-length bv))
	   (pt-blocks (div pt-len block-size))
	   (ct-len (if (zero? (mod pt-len block-size))
		       (* (+ pt-blocks 2) block-size)
		       (* (+ pt-blocks 1) block-size)))
	   (r (symmetric-cipher:encrypt-last-block!
	       (symmetric-cipher:init! cipher
				       (symmetric-cipher-operation encrypt)
				       symmetric-key param)
	       bv 0 (make-bytevector ct-len) 0)))
      (symmetric-cipher:done! cipher)
      r))))

(define symmetric-cipher:decrypt-bytevector
  (case-lambda
   ((cipher symmetric-key bv)
    (symmetric-cipher:decrypt-bytevector cipher symmetric-key #f bv))
   ((cipher symmetric-key param bv)
    (unless (symmetric-cipher? cipher)
      (springkussen-assertion-violation 'symmetric-cipher:decrypt-bytevector
					"Symmetric cipher is required" cipher))
    (unless (symmetric-key? symmetric-key)
      (springkussen-assertion-violation 'symmetric-cipher:decrypt-bytevector
					"Symmetric key is required"))
    (unless (or (not param) (cipher-parameter? param))
      (springkussen-assertion-violation 'symmetric-cipher:decrypt-bytevector
					"Cipher parameter of #f is required"))
    (unless (bytevector? bv)
      (springkussen-assertion-violation 'symmetric-cipher:decrypt-bytevector
					"Bytevector is required" bv))
    (let* ((block-size (symmetric-cipher:block-size cipher))
	   (ct-len (bytevector-length bv))
	   (buf (make-bytevector ct-len))
	   (r (symmetric-cipher:decrypt-last-block!
	       (symmetric-cipher:init! cipher
				       (symmetric-cipher-operation decrypt)
				       symmetric-key param)
	       bv 0 buf 0)))
      (symmetric-cipher:done! cipher)
      (sub-bytevector buf 0 r)))))

(define (symmetric-cipher:block-size cipher)
  (unless (symmetric-cipher? cipher)
    (springkussen-assertion-violation 'symmetric-cipher:block-size
				      "Symmetric cipher is required" cipher))
  (let* ((spec (symmetric-cipher-cipher-spec cipher))
	 (mode (symmetric-cipher-spec-mode spec))
	 (scheme (symmetric-cipher-spec-scheme spec)))
    (symmetric-scheme-descriptor-block-size scheme)))

(define *operation-enum-set* (enum-set-universe (symmetric-cipher-operations)))

(define symmetric-cipher:init!
  (case-lambda
   ((cipher op symmetric-key)
    (symmetric-cipher:init! cipher op symmetric-key #f))
   ((cipher op symmetric-key param)
    (unless (symmetric-cipher? cipher)
      (springkussen-assertion-violation 'symmetric-cipher:init!
       "Symmetric cipher is required" cipher))
    (unless (symmetric-key? symmetric-key)
      (springkussen-assertion-violation 'symmetric-cipher:init!
					"Symmetric key is required"))
    (unless (enum-set-member? op *operation-enum-set*)
      (springkussen-assertion-violation 'symmetric-cipher:init!
					"Unknown operation" op))
    (let* ((cipher-spec (symmetric-cipher-cipher-spec cipher))
	   (scheme (symmetric-cipher-spec-scheme cipher-spec))
	   (mode (symmetric-cipher-spec-mode cipher-spec))
	   (mode-key (symmetric-mode-descriptor:start
		      mode scheme (symmetric-key-raw-value symmetric-key)
		      param)))
      (symmetric-cipher-op-set! cipher op)
      (symmetric-cipher-mode-key-set! cipher mode-key)
      cipher))))

(define (symmetric-cipher:encrypt! cipher pt ps ct cs)
  (unless (symmetric-cipher? cipher)
    (springkussen-assertion-violation 'symmetric-cipher:encrypt!
				      "Symmetric cipher is required" cipher))
  (unless (eq? (symmetric-cipher-operation encrypt)
	       (symmetric-cipher-op cipher))
    (springkussen-error 'symmetric-cipher:encrypt!
			"Cipher is not encryption mode"))
  (unless (and (bytevector? pt) (bytevector? ct))
    (springkussen-assertion-violation 'symmetric-cipher:encrypt!
				      "Bytevector is required"))
  (let ((block-size (symmetric-cipher:block-size cipher))
	(pt-len (- (bytevector-length pt) ps))
	(ct-len (- (bytevector-length ct) cs))
	(spec (symmetric-cipher-cipher-spec cipher)))
    (unless (zero? (div pt-len block-size))
      (springkussen-error 'symmetric-cipher:encrypt!
			  "Plain text size must be multiple of block size"))
    (unless (= pt-len ct-len)
      (springkussen-assertion-violation 'symmetric-cipher:encrypt!
	  "Output cipher text buffer is too small for the input"))
    (let ((mode (symmetric-cipher-spec-mode spec))
	  (mode-key (symmetric-cipher-mode-key cipher)))
      (symmetric-mode-descriptor:encrypt mode mode-key pt ps ct cs))))
    
(define (symmetric-cipher:encrypt-last-block! cipher pt ps ct cs)
  (unless (symmetric-cipher? cipher)
    (springkussen-assertion-violation 'symmetric-cipher:encrypt-last-block!
				      "Symmetric cipher is required" cipher))
  (unless (eq? (symmetric-cipher-operation encrypt)
	       (symmetric-cipher-op cipher))
    (springkussen-error 'symmetric-cipher:encrypt-last-block!
			"Cipher is not encryption mode"))
  (unless (and (bytevector? pt) (bytevector? ct))
    (springkussen-assertion-violation 'symmetric-cipher:encrypt-last-block!
				      "Bytevector is required"))
  (let* ((block-size (symmetric-cipher:block-size cipher))
	 (pt-len (- (bytevector-length pt) ps))
	 (pt-blocks (div pt-len block-size))
	 (pt-mod (mod pt-len block-size))
	 (ct-len (- (bytevector-length ct) cs))
	 (spec (symmetric-cipher-cipher-spec cipher))
	 (padder (symmetric-cipher-padder cipher))
	 (mode (symmetric-cipher-spec-mode spec))
	 (mode-key (symmetric-cipher-mode-key cipher)))
    (when (and padder
	       (< (div ct-len block-size)
		  (+ pt-blocks (if (zero? pt-mod) 1 0))))
      (springkussen-assertion-violation 'symmetric-cipher:encrypt-last-block!
       "Output cipher text buffer is too small"))
    (unless (or padder (zero? (mod pt-len block-size)))
      (springkussen-assertion-violation 'symmetric-cipher:encrypt-last-block!
	"Padder is not specified but plain text is not multiple of block size"))
    (if padder
	(symmetric-mode-descriptor:encrypt
	 mode mode-key (padder (sub-bytevector pt ps) block-size) 0 ct cs)
	(symmetric-mode-descriptor:encrypt mode mode-key pt ps ct cs))))

(define (symmetric-cipher:decrypt! cipher ct cs pt ps)
  (unless (symmetric-cipher? cipher)
    (springkussen-assertion-violation 'symmetric-cipher:decrypt!
				      "Symmetric cipher is required" cipher))
  (unless (eq? (symmetric-cipher-operation decrypt)
	       (symmetric-cipher-op cipher))
    (springkussen-error 'symmetric-cipher:decrypt!
			"Cipher is not decryption mode"))
  (unless (and (bytevector? pt) (bytevector? ct))
    (springkussen-assertion-violation 'symmetric-cipher:decrypt!
				      "Bytevector is required"))
  (let ((block-size (symmetric-cipher:block-size cipher))
	(pt-len (- (bytevector-length pt) ps))
	(ct-len (- (bytevector-length ct) cs))
	(spec (symmetric-cipher-cipher-spec cipher)))
    (unless (zero? (div ct-len block-size))
      (springkussen-error 'symmetric-cipher:decrypt!
			  "Cipher text size must be multiple of block size"))
    (unless (= pt-len ct-len)
      (springkussen-assertion-violation 'symmetric-cipher:decrypt!
	  "Output plain text buffer is too small for the input"))
    (let ((mode (symmetric-cipher-spec-mode spec))
	  (mode-key (symmetric-cipher-mode-key cipher)))
      (symmetric-mode-descriptor:decrypt mode mode-key pt ps ct cs))))
  
(define (symmetric-cipher:decrypt-last-block! cipher ct cs pt ps)
  (unless (symmetric-cipher? cipher)
    (springkussen-assertion-violation 'symmetric-cipher:decrypt-last-block!
				      "Symmetric cipher is required" cipher))
  (unless (eq? (symmetric-cipher-operation decrypt)
	       (symmetric-cipher-op cipher))
    (springkussen-error 'symmetric-cipher:decrypt-last-block!
			"Cipher is not encryption mode"))
  (unless (and (bytevector? pt) (bytevector? ct))
    (springkussen-assertion-violation 'symmetric-cipher:decrypt-last-block!
				      "Bytevector is required"))

  (let* ((block-size (symmetric-cipher:block-size cipher))
	 (pt-len (- (bytevector-length pt) ps))
	 (ct-len (- (bytevector-length ct) cs))
	 (spec (symmetric-cipher-cipher-spec cipher))
	 (unpadder (symmetric-cipher-unpadder cipher))
	 (mode (symmetric-cipher-spec-mode spec))
	 (mode-key (symmetric-cipher-mode-key cipher)))
    (unless (zero? (mod ct-len block-size))
      (springkussen-error 'symmetric-cipher:decrypt-last-block!
			  "Cipher text size must be multiple of block size"))
    (let* ((buf (make-bytevector pt-len))
	   (r (symmetric-mode-descriptor:decrypt mode mode-key ct cs buf 0))
	   (unpad (or (and unpadder (unpadder r block-size)) r)))
      (when (< pt-len (bytevector-length unpad))
	(springkussen-error 'symmetric-cipher:decrypt-last-block!
			    "Plain text buffer is too small"))
      (bytevector-copy! unpad 0 pt ps (bytevector-length unpad))
      (bytevector-length unpad))))
  
(define (symmetric-cipher:done! cipher)
  ;; Reset cipher
  (symmetric-cipher-op-set! cipher #f)
  (symmetric-cipher-mode-key-set! cipher #f)
  cipher)

(define (pkcs7-padding)
  (define (pad bv block-size)
    (let* ((len (bytevector-length bv))
	   (mod (mod len block-size))
	   (padding (- block-size mod)))
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
