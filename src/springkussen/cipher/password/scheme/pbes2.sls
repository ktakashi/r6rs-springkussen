;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/password/scheme/pbes2.sls - PBES2
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
(library (springkussen cipher password scheme pbes2)
    (export pbes2-scheme-descriptor
	    make-pbes2-cipher-encryption-mode-parameter
	    pbes2-cipher-encryption-mode-parameter?)
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen cipher parameter)
	    (springkussen cipher symmetric)
	    (springkussen cipher symmetric scheme descriptor)
	    (springkussen cipher password kdf)
	    (springkussen cipher password scheme descriptor))

(define-syntax define-pbes2-parameter (make-define-cipher-parameter))
(define-pbes2-parameter pbes2-cipher-encryption-mode-parameter
  make-pbes2-cipher-encryption-mode-parameter
  pbes2-cipher-encryption-mode-parameter?
  (mode pbes2-cipher-parameter-encryption-mode))

(define-record-type pbes2-state
  (fields cipher))

(define *default-iteration* 1024)

(define (pbes2-init scheme op password param)
  (define salt (pbe-cipher-parameter-salt param))
  (define kdf (or (pbe-cipher-parameter-kdf param #f) (make-pbkdf-2 #f)))
  (define iteration (pbe-cipher-parameter-iteration param *default-iteration*))
  (define dk-len
    (or (pbe-cipher-parameter-key-size param #f)
	(select-key-length (symmetric-scheme-descriptor-key-length* scheme))))
  (unless (string? password)
    (springkussen-assertion-violation 'pbes2-init "Password must be a string"))
  (let* ((dk (kdf (string->utf8 password) salt iteration dk-len))
	 (mode (pbes2-cipher-parameter-encryption-mode param *mode:cbc*))
	 (cipher-spec (symmetric-cipher-spec-builder
		      (scheme scheme)
		      (mode mode)))
	 (cipher (make-symmetric-cipher cipher-spec)))
    ;; we pass the param so that underlying scheme can take the parameter
    (symmetric-cipher:init! cipher op (make-symmetric-key dk) param)
    (make-pbes2-state cipher)))

(define (pbes2-encrypt state pt ps ct cs)
  (let ((cipher (pbes2-state-cipher state)))
    (symmetric-cipher:encrypt! cipher pt ps ct cs)))

(define (pbes2-decrypt state ct cs pt ps)
  (let ((cipher (pbes2-state-cipher state)))
    (symmetric-cipher:decrypt! cipher ct cs pt ps)))

(define (pbes2-done state)
  (symmetric-cipher:done! (pbes2-state-cipher state)))

(define (select-key-length key-length*)
  (define (pair/null? p) (or (pair? p) (null? p)))
  (cond ((number? key-length*) key-length*)
	((pair? key-length*)
	 (if (pair/null? (cdr key-length*))
	     ;; take the last one (the biggest)
	     (let loop ((k key-length*))
	       (if (null? (cdr k))
		   (car k)
		   (loop (cdr k))))
	     ;; range, so take the upper bound
	     (cdr key-length*)))
	(else (springkussen-assertion-violation 'select-key-length
		"Invalid encryption scheme descriptor"))))

(define pbes2-scheme-descriptor
  (pbe-scheme-descriptor-builder
   (name "PBES2")
   (starter pbes2-init)
   (encryptor pbes2-encrypt)
   (decryptor pbes2-decrypt)
   (finalizer pbes2-done)))

)
