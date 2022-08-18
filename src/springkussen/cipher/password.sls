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

	    *mode:ecb* *mode:cbc*

	    make-cipher-parameter cipher-parameter?
	    mode-parameter? 
	    make-iv-paramater iv-parameter?

	    pkcs7-padding no-padding
	    )
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen cipher symmetric)
	    (springkussen cipher password kdf)
	    (springkussen cipher password scheme descriptor)
	    (springkussen cipher password scheme pbes1)
	    (springkussen cipher password scheme pbes2))

(define (make-pbe-cipher desc param)
  (define spec (symmetric-cipher-spec-builder
		(scheme (pbe-cipher-parameter-encryption-scheme param))
		(mode desc)))
  (make-symmetric-cipher spec))

)

