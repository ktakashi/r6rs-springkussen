;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/symmetric/mode/cbc.sls - CBC mode
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
(library (springkussen cipher symmetric mode cbc)
    (export cbc-mode-descriptor)
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen misc bytevectors)
	    (springkussen cipher symmetric mode descriptor)
	    (springkussen cipher symmetric mode parameter)
	    (springkussen cipher symmetric scheme descriptor))

(define-record-type symmetric-cbc
  (fields spec iv key block-length))

(define (cbc-start spec key param)
  (unless (iv-parameter? param)
    (springkussen-assertion-violation 'start "CBC mode requires IV"))
  (let ((skey (symmetric-scheme-descriptor:setup spec key 
	       (or (parameter-round param 0) 0)))
	(blocklen (symmetric-scheme-descriptor-block-size spec)))
    (make-symmetric-cbc spec (bytevector-copy (parameter-iv param))
			skey blocklen)))

(define (cbc-setiv cbc iv)
  (unless (= (bytevector-length iv) (symmetric-cbc-block-length cbc))
    (springkussen-assertion-violation 'setiv "Invalid argument"))
  (bytevector-copy! iv 0 (symmetric-cbc-iv cbc) 0 (bytevector-length iv)))

(define (cbc-getiv cbc) (bytevector-copy (symmetric-cbc-iv cbc)))

(define (cbc-encrypt cbc pt)
  (define blocklen (symmetric-cbc-block-length cbc))
  (define pt-len (bytevector-length pt))
  (define iv (symmetric-cbc-iv cbc))
  
  (unless (zero? (mod pt-len blocklen))
    (springkussen-assertion-violation 'encrypt "invalid argument"))
  (let ((ct (make-bytevector (bytevector-length pt)))
	(encrypt (symmetric-scheme-descriptor-encryptor
		  (symmetric-cbc-spec cbc)))
	(key (symmetric-cbc-key cbc)))
    (let loop ((i 0))
      (if (= i pt-len)
	  ct
	  (let ((b (encrypt (bytevector-xor! iv 0 pt i blocklen) 0 ct i key)))
	    (unless (= b blocklen) 
	      (springkussen-error 'encrypt "invalid encryption"))
	    (bytevector-copy! ct i iv 0 blocklen)
	    (loop (+ i blocklen)))))))

(define (cbc-decrypt cbc ct)
  (define blocklen (symmetric-cbc-block-length cbc))
  (define ct-len (bytevector-length ct))
  (define iv (symmetric-cbc-iv cbc))
  
  (unless (zero? (mod ct-len blocklen))
    (springkussen-assertion-violation 'decrypt "invalid argument"))
  (let ((pt (make-bytevector (bytevector-length ct)))
	(decrypt (symmetric-scheme-descriptor-decryptor
		  (symmetric-cbc-spec cbc)))
	(key (symmetric-cbc-key cbc)))
    (let loop ((i 0))
      (if (= i ct-len)
	  pt
	  (let ((b (decrypt ct i pt i key)))
	    (unless (= b blocklen)
	      (springkussen-error 'decrypt "invalid decryption"))
	    (bytevector-xor! pt i iv 0 blocklen)
	    (bytevector-xor! iv 0 ct i blocklen)
	    (loop (+ i blocklen)))))))

(define (cbc-done cbc)
  (symmetric-scheme-descriptor:done (symmetric-cbc-spec cbc)
				    (symmetric-cbc-key cbc)))

(define cbc-mode-descriptor
  (symmetric-mode-descriptor-builder
   (name "CBC")
   (starter cbc-start)
   (encryptor cbc-encrypt)
   (decryptor cbc-decrypt)
   (finalizer cbc-done)
   (iv-setter cbc-setiv)
   (iv-getter cbc-getiv)
   ))

)

