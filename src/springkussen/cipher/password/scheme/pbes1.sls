;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/password/scheme/pbes1.sls - PBES1
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

;; we implement PBES as a mode of the symmetric cipher
;; so that we can use it as a framework :)

#!r6rs
(library (springkussen cipher password scheme pbes1)
    (export pbes1-scheme-descriptor)
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen cipher symmetric)
	    (springkussen cipher password kdf)
	    (springkussen cipher password scheme descriptor)
	    (springkussen misc bytevectors))

(define-record-type pbes1-state
  (fields cipher))

(define *default-iteration* 1024)

(define (pbes1-init scheme op password param)
  (define salt (pbe-cipher-parameter-salt param))
  (define block-size (symmetric-scheme-descriptor-block-size scheme))
  (define salt-len block-size)
  (define dk-len block-size)
  (define kdf (or (pbe-cipher-parameter-kdf param #f) (make-pbkdf-1 #f)))
  (define iteration (pbe-cipher-parameter-iteration param *default-iteration*))
  (unless (string? password)
    (springkussen-assertion-violation 'pbes1-init "Password must be a string"))
  (let ((dk (kdf (string->utf8 password) salt iteration (* block-size 2))))
    (let-values (((k iv) (bytevector-split-at* dk dk-len)))
      (let* ((cipher-spec (symmetric-cipher-spec-builder
			   (scheme scheme)
			   (mode *mode:cbc*)))
	     (cipher (make-symmetric-cipher cipher-spec)))
	(symmetric-cipher:init! cipher
				op
				(make-symmetric-key k)
				(make-iv-paramater iv))
	(make-pbes1-state cipher)))))

(define (pbes1-encrypt state pt ps ct cs)
  (let ((cipher (pbes1-state-cipher state)))
    (symmetric-cipher:encrypt! cipher pt ps ct cs)
    ct))

(define (pbes1-decrypt state ct cs pt ps)
  (let ((cipher (pbes1-state-cipher state)))
    (symmetric-cipher:decrypt! cipher ct cs pt ps)
    pt))

(define (pbes1-done state)
  (symmetric-cipher:done! (pbes1-state-cipher state)))

(define pbes1-scheme-descriptor
  (pbe-scheme-descriptor-builder
   (name "PBES1")
   (starter pbes1-init)
   (encryptor pbes1-encrypt)
   (decryptor pbes1-decrypt)
   (finalizer pbes1-done)))

)
