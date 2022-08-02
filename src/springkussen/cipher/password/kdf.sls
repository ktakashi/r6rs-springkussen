;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/password/kdf.sls - PBE KDF
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
(library (springkussen cipher password kdf)
    (export pbe-kdf-parameter?

	    make-pbkdf-1
	    make-pbe-kdf-digest-parameter pbe-kdf-digest-parameter?
	    
	    make-pbkdf-2
	    make-pbe-kdf-prf-parameter pbe-kdf-prf-parameter?

	    mac->pbkdf2-prf
	    make-partial-hmac-parameter
	    )
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen cipher parameter)
	    (springkussen digest)
	    (springkussen mac)
	    (springkussen misc bytevectors))

(define-record-type pbe-kdf-parameter (parent <cipher-parameter>))
(define-syntax define-pbe-kdf-parameter 
  (make-define-cipher-parameter pbe-kdf-parameter))

(define-pbe-kdf-parameter pbe-kdf-digest-parameter
  make-pbe-kdf-digest-parameter pbe-kdf-digest-parameter?
  (md pbe-kdf-parameter-md))

(define (make-pbkdf-1 param)
  (define md (pbe-kdf-parameter-md param *digest:sha1*))
  (define digest-len (digest-descriptor-digest-size md))
  (define digester (make-digester md))
  (lambda (P S c dk-len)
    (when (> dk-len digest-len)
      (springkussen-assertion-violation 'pbkdf-1 "Derived key too long"))
    (let* ((buf (make-bytevector digest-len))
	   (dk (make-bytevector  dk-len)))
      (digester:init! digester)
      (digester:process! digester P)
      (digester:process! digester S)
      (digester:done! digester buf)
      (do ((i 0 (+ i 1)) (c (- c 1)))
	  ((= i c)
	   (bytevector-copy! buf 0 dk 0 dk-len)
	   dk)
	(digester:digest! digester buf buf)))))

(define-pbe-kdf-parameter pbe-kdf-prf-parameter
  make-pbe-kdf-prf-parameter pbe-kdf-prf-parameter?
  (prf pbe-kdf-parameter-prf))

(define (make-pbkdf-2 param)
  (define make-prf (or (pbe-kdf-parameter-prf param #f) *default-prf*))

  (define (F prf h-len P S c i)
    (define (concat bv int)
      (let* ((len (bytevector-length bv))
	     (new (make-bytevector (+ len 4)))
	     (iv  (make-bytevector 4)))
	(bytevector-u32-set! iv 0 int (endianness big))
	(bytevector-copy! bv 0 new 0 len)
	(bytevector-copy! iv 0 new len 4)
	new))
    (let ((buf (make-bytevector h-len))
	  (out (make-bytevector h-len)))
      (do ((j 0 (+ j 1)))
	  ((= j c) out)
	(cond ((zero? j)
	       (prf (concat S i) out)
	       (bytevector-copy! out 0 buf 0 h-len))
	      (else
	       (prf buf buf)
	       (bytevector-xor! out 0 buf 0 h-len))))))

  (define (finish dk-len h-len ts)
    (let ((dk (make-bytevector dk-len)))
      (let loop ((stored 0) (i 0))
	(if (= stored dk-len)
	    dk
	    (let ((count (min (- dk-len stored) h-len)))
	      (bytevector-copy! (vector-ref ts i) 0 dk stored count)
	      (loop (+ count stored) (+ i 1)))))))
  
  (lambda (P S c dk-len)
    (let-values (((prf h-len) (make-prf P)))
      (when (> dk-len (* #xffffffff h-len))
	(springkussen-assertion-violation 'pbkdf-2 "Derived key too long"))
      (let* ((l (ceiling (/ dk-len h-len)))
	     (ts (make-vector l)))
	(do ((i 0 (+ i 1)))
	    ((= i l) (finish dk-len h-len ts))
	  (vector-set! ts i (F prf h-len P S c (+ i 1))))))))

(define (make-partial-hmac-parameter md)
  (lambda (S)
    (make-hmac-parameter S md)))

(define (mac->pbkdf2-prf mac-desc param)
  (lambda (S)
    (let ((mac (make-mac mac-desc (param S))))
      (values (lambda (m out) (mac:generate-mac! mac m out))
	      (mac:mac-size mac)))))

(define *default-prf*
  (mac->pbkdf2-prf *mac:hmac* (make-partial-hmac-parameter *digest:sha1*)))

      
)

