;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/mac/hmac.sls - HMAC 
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
(library (springkussen mac hmac)
    (export hmac-descriptor

	    make-hmac-parameter hmac-parameter?)
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen digest)
	    (springkussen mac descriptor))

(define-record-type hmac-state
  (fields md
	  digester
	  i-key
	  key))

(define (hmac-init param)
  (define (expand! digester i-key blen hlen)
    (let ((key (make-bytevector blen 0))
	  (klen (bytevector-length i-key)))
      (cond ((> klen blen)
	     (digester:digest! digester i-key key)
	     (values key hlen))
	    (else
	     (bytevector-copy! i-key 0 key 0 klen)
	     (values key klen)))))
  (define md (mac-parameter-digest param))
  (define i-key (mac-parameter-key param))
  (define blen (digest-descriptor-block-size md))
  (define hlen (digest-descriptor-digest-size md))
  (let ((buffer (make-bytevector blen))
	(digester (make-digester md)))
    (let-values (((key klen) (expand! digester i-key blen hlen)))
      (do ((i 0 (+ i 1)))
	  ((= i blen))
	(bytevector-u8-set! buffer i
			    (bitwise-xor (bytevector-u8-ref key i) #x36)))
      (digester:init! digester)
      (digester:process! digester buffer)
      (make-hmac-state md digester i-key key))))

(define (hmac-process state in start end)
  (digester:process! (hmac-state-digester state) in start end))

(define (hmac-done state out start len)
  (define md (hmac-state-md state))
  (define blen (digest-descriptor-block-size md))
  (define hlen (digest-descriptor-digest-size md))
  (define key (hmac-state-key state))
  (define digester (hmac-state-digester state))
  (let ((isha (make-bytevector hlen))
	(buffer (make-bytevector blen)))
    (digester:done! digester isha)
    (do ((i 0 (+ i 1)))
	((= i blen))
      (bytevector-u8-set! buffer i
			  (bitwise-xor (bytevector-u8-ref key i) #x5c)))
    (digester:init! digester)
    (digester:process! digester buffer)
    (digester:process! digester isha)
    (digester:done! digester buffer)
    (bytevector-copy! buffer 0 out start (min hlen len))
    out))

(define (get-digest who sp)
  (cond ((hmac-state? sp) (hmac-state-md sp))
	((hmac-parameter? sp) (mac-parameter-digest sp))
	(else (springkussen-assertion-violation who "Unexpected argument" sp))))

(define (hmac-size state/param)
  (digest-descriptor-digest-size (get-digest 'mac-size state/param)))

(define md->oid digest-descriptor-oid)
(define md-oid->hmac-oid
  `(
    (,(md->oid *digest:md5*) . "1.3.6.1.5.5.8.1.1") ;; hmac-md5
    ;; (,(md->oid *digest:sha1*) . "1.3.6.1.5.5.8.1.2")	 ;; hmac-sha1
    ("1.3.6.1.4.1.11591.12.2" . "1.3.6.1.5.5.8.1.3") ;; hmac-tiger (tbs)
    ("1.0.10118.3.0.49" . "1.3.6.1.5.5.8.1.4") ;; hmac-ripemd160 (tbs)

    ;; hmmm, which one should we use? though this one seems more common
    (,(md->oid *digest:sha1*)   . "1.2.840.113549.2.7")	 ;; hmac-sha1
    (,(md->oid *digest:sha224*) . "1.2.840.113549.2.8") ;; hmac-sha224
    (,(md->oid *digest:sha256*) . "1.2.840.113549.2.9") ;; hmac-sha256
    (,(md->oid *digest:sha384*) . "1.2.840.113549.2.10") ;; hmac-sha384
    (,(md->oid *digest:sha512*) . "1.2.840.113549.2.11") ;; hmac-sha512
    ;; seems no hmac-sha512/224 or hmac-sha512/256
    ;; TODO more if we want
    ))
    
(define (hmac-oid state/param)
  (define oid (digest-descriptor-oid (get-digest 'mac-oid state/param)))
  (cond ((assoc oid md-oid->hmac-oid) => cdr)
	(else #f)))

;; Famous workaround...
(define-syntax define-mac-parameter (make-define-mac-parameter))

(define-mac-parameter <hmac-parameter>
  make-hmac-parameter hmac-parameter?
  (key mac-parameter-key)
  (digest mac-parameter-digest))

(define hmac-descriptor
  (mac-descriptor-builder
   (name "HMAC")
   (mac-sizer hmac-size)
   (oid-retriever hmac-oid)
   (starter hmac-init)
   (processor hmac-process)
   (finalizer hmac-done)))

)
