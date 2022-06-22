;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/symmetric/mode/ecb.sls - ECB mode
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
(library (springkussen cipher symmetric mode ecb)
    (export ecb-mode-descriptor)
    (import (rnrs)
	    (springkussen cipher symmetric mode descriptor)
	    (springkussen cipher symmetric mode parameter)
	    (springkussen cipher symmetric scheme descriptor))

(define-record-type symmetric-ecb
  (fields spec key block-length))

(define (ecb-start spec key param)
  (let ((skey (symmetric-scheme-descriptor:setup spec key 
	       (or (parameter-round param 0) 0)))
	(blocklen (symmetric-scheme-descriptor-block-size spec)))
    (make-symmetric-ecb spec skey blocklen)))

(define (ecb-encrypt ecb pt)
  (define blocklen (symmetric-ecb-block-length ecb))
  (define pt-len (bytevector-length pt))
  (unless (zero? (mod pt-len blocklen))
    (error 'ecb-encrypt "invalid argument"))
  (let ((ct (make-bytevector (bytevector-length pt)))
	(encrypt (symmetric-scheme-descriptor-encryptor
		  (symmetric-ecb-spec ecb)))
	(key (symmetric-ecb-key ecb)))
    (let loop ((i 0))
      (if (= i pt-len)
	  ct
	  (let ((b (encrypt pt i ct i key)))
	    (unless (= b blocklen) 
	      (error 'ecb-encrypt "invalid encryption"))
	    (loop (+ i blocklen)))))))

(define (ecb-decrypt ecb ct)
  (define blocklen (symmetric-ecb-block-length ecb))
  (define ct-len (bytevector-length ct))
  (unless (zero? (mod ct-len blocklen))
    (error 'ecb-decrypt "invalid argument"))
  (let ((pt (make-bytevector (bytevector-length ct)))
	(decrypt (symmetric-scheme-descriptor-decryptor
		  (symmetric-ecb-spec ecb)))
	(key (symmetric-ecb-key ecb)))
    (let loop ((i 0))
      (if (= i ct-len)
	  pt
	  (let ((b (decrypt ct i pt i key)))
	    (unless (= b blocklen)
	      (error 'ecb-decrypt "invalid encryption"))
	    (loop (+ i blocklen)))))))

(define (ecb-done ecb)
  (symmetric-scheme-descriptor:done (symmetric-ecb-spec ecb)
				    (symmetric-ecb-key ecb)))

(define ecb-mode-descriptor
  (symmetric-mode-descriptor-builder
   (starter ecb-start)
   (encryptor ecb-encrypt)
   (decryptor ecb-decrypt)
   (finalizer ecb-done)))

)

