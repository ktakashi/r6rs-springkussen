;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/asymmetric/encoding.sls - Asymmetric encodingd
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
(library (springkussen cipher asymmetric encoding)
    (export pkcs1-v1.5-encoding

	    encoding-parameter?

	    random-generator-encoding-parameter?
	    make-random-generator-encoding-parameter
	    encoding-parameter-random-generator
	    )
    (import (rnrs)
	    (springkussen cipher asymmetric key)
	    (springkussen cipher asymmetric scheme descriptor)
	    (springkussen cipher parameter)
	    (springkussen random)
	    (springkussen conditions)
	    (springkussen misc record))

(define-record-type encoding-parameter
  (parent <cipher-parameter>))

(define-syntax define-encoding-parameter
  (make-define-cipher-parameter encoding-parameter))

(define-encoding-parameter <random-generator-encoding-parameter>
  make-random-generator-encoding-parameter random-generator-encoding-parameter?
  (prng encoding-parameter-random-generator))

(define pkcs1-v1.5-encoding
  (case-lambda
   ((descriptor) (pkcs1-v1.5-encoding descriptor #f))
   ((descriptor param)
    (define prng
      (or (and param
	       (encoding-parameter-random-generator param
						    default-random-generator))
	  default-random-generator))
    ;; Encode with
    ;;  - private key = signature  = EMSA-PKCS1-v1.5
    ;;  - public key  = encryption = RSAES-PKCS1-v1_5
    ;; Decode with
    ;;  - private key = encryption = RSAES-PKCS1-v1_5
    ;;  - public key  = signature  = EMSA-PKCS1-v1.5
    (define (encode data state) ;; encryption / sign
      (define for-private-key? (asymmetric-state-for-private-key? state))
      (define k
	(asymmetric-scheme-descriptor:get-block-size descriptor state))
      (define message-length (bytevector-length data))
      (when (> (+ message-length 11) k)
	(springkussen-assertion-violation 'pkcs1-v1.5-encode
			  "Too much data for PKCS#1 v1.5 encoding"))
      ;; 0x00 || 0x0(1|2) || PS || 0x00 || M
      (let* ((ps-length (- k message-length 3))
	     (bv (make-bytevector (+ 2 ps-length 1 message-length))))
	(cond (for-private-key?
	       (bytevector-u8-set! bv 1 2) ;; PKCS1-v1.5-EME
	       (random-generator:read-random-bytes! prng bv 2 ps-length)
	       (do ((i 0 (+ i 1)) (bv (make-bytevector 1)))
		   ((= i ps-length) #t)
		 ;; transform zero bytes (if any) to non-zero random bytes
		 (when (zero? (bytevector-u8-ref bv (+ i 2)))
		   (do ((r (random-generator:read-random-bytes! prng bv)
			   (random-generator:read-random-bytes! prng bv)))
		       ((not (zero? (bytevector-u8-ref r 0)))
			(bytevector-u8-set! bv (+ i 2)
					    (bytevector-u8-ref r 0)))))))
	      (else (bytevector-fill! bv #xFF)
		    (bytevector-u8-set! bv 1 1)))
	(bytevector-u8-set! bv 0 0)
	;; set block-type
	(bytevector-u8-set! bv (+ 2 ps-length) 0) ;; mark end of the paddding
	(bytevector-copy! data 0 bv (+ 2 ps-length 1) message-length)
	bv))
    
    (define (decode data state)
      ;; search the end of padding, in case of invalid padding format
      ;; we go through the entire bytevector to avoid oracle attack
      (define (search-end-padding data)
	(define len (bytevector-length data))
	(let loop ((i 2) (valid? #t))
	  (if (>= i len)
	      #f ;; not found
	      (let ((v (bytevector-u8-ref data i)))
		(cond ((zero? v) i)
		      ((or (eqv? type 2) (and (eqv? type 1) (= v #xFF)))
		       (loop (+ i 1) valid?))
		      (else (loop (+ i 1) #f)))))))

      (define for-private-key? (asymmetric-state-for-private-key? state))
      (define k
	(asymmetric-scheme-descriptor:get-block-size descriptor state))
      (define m-len (bytevector-length data))
      (define type (and (>= m-len 2) (bytevector-u8-ref data 1)))

      (let ((from (search-end-padding data)))
	(when (or (< m-len 1) (not (zero? (bytevector-u8-ref data 0)))
		  (not from) (>= from k) (< from 9))
	  (springkussen-error 'pkcs1-v1.5-decode "Invalid padding"))
	(let* ((len (- m-len from))
	       (bv (make-bytevector len 0)))
	    (bytevector-copy! data from bv 0 len)
	    bv)))
    (values encode decode))))
  


)
