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
	    oaep-encoding
	    
	    encoding-parameter?

	    random-generator-encoding-parameter?
	    make-random-generator-encoding-parameter

	    make-digest-encoding-parameter digest-encoding-parameter?
	    make-mgf-digest-encoding-parameter mgf-digest-encoding-parameter?
	    make-mgf-encoding-parameter mgf-encoding-parameter?
	    make-label-encoding-parameter label-encoding-parameter?
	    ;; needs signature so put it here for now
	    ;; maybe move to (springkussen misc mgf)?
	    mgf-1
	    )
    (import (rnrs)
	    (springkussen cipher asymmetric key)
	    (springkussen cipher asymmetric scheme descriptor)
	    (springkussen cipher parameter)
	    (springkussen digest)
	    (springkussen random)
	    (springkussen conditions)
	    (springkussen misc bytevectors)
	    (springkussen misc record))

(define-record-type encoding-parameter
  (parent <cipher-parameter>))

(define-syntax define-encoding-parameter
  (make-define-cipher-parameter encoding-parameter))

(define-encoding-parameter <random-generator-encoding-parameter>
  make-random-generator-encoding-parameter random-generator-encoding-parameter?
  (prng encoding-parameter-random-generator))

(define-encoding-parameter <digest-encoding-parameter>
  make-digest-encoding-parameter digest-encoding-parameter?
  (digest encoding-parameter-digest))

(define-encoding-parameter <mgf-digest-encoding-parameter>
  make-mgf-digest-encoding-parameter mgf-digest-encoding-parameter?
  (mgf-sha encoding-parameter-mgf-sha))
;; I've never seen other MGF other than MGF1
(define-encoding-parameter (<mgf-encoding-parameter> <mgf-digest-encoding-parameter>)
  make-mgf-encoding-parameter mgf-encoding-parameter?
  (mgf     encoding-parameter-mgf))

(define-encoding-parameter <label-encoding-parameter>
  make-label-encoding-parameter label-encoding-parameter?
  (label  encoding-parameter-label))

(define (mgf-1 mgf-seed mask-length md)
  (when (> mask-length #x100000000) ;; 2^32
    (springkussen-assertion-violation 'mgf-1 "Mask too long"))
  (let* ((hash-len (digest-descriptor-digest-size md))
	 (digester (make-digester md))
	 (limit (+ 1 (div mask-length hash-len)))
	 (len   (bytevector-length mgf-seed))
	 (buf   (make-bytevector (+ len 4) 0))
	 (T     (make-bytevector mask-length 0)))
    (bytevector-copy! mgf-seed 0 buf 0 len)
    (do ((counter 0 (+ counter 1)))
	((= counter limit) T)
      (bytevector-u32-set! buf len counter (endianness big))
      (let ((index (* counter hash-len)))
	(if (> (+ index hash-len) mask-length)
	    (bytevector-copy! (digester:digest digester buf) 0 T index
			      (- mask-length index))
	    (bytevector-copy! (digester:digest digester buf) 0 T index
			      hash-len))))))

(define oaep-encoding
  (case-lambda
   ((descriptor) (oaep-encoding descriptor #f))
   ((descriptor param)
    ;; Default is mgf1SHA1...
    ;; https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.2.1
    (define md (encoding-parameter-digest param *digest:sha1*))
    (define hlen (digest-descriptor-digest-size md))
    (define mgf (or (encoding-parameter-mgf param mgf-1) mgf-1))
    (define mgf-sha (encoding-parameter-mgf-sha param *digest:sha1*))
    (define label (encoding-parameter-label param #vu8()))
    (define digester (make-digester md))
    (define lhash (digester:digest digester label))
    (define prng
      (encoding-parameter-random-generator param default-random-generator))
    
    (define (encode data state)
      (define k
	(asymmetric-scheme-descriptor:get-block-size descriptor state))
      (define ps-len (- k (bytevector-length data) (* hlen 2) 2))

      (when (> (bytevector-length data) (- k 2 (* hlen 2)))
	(springkussen-assertion-violation 'oaep-encoding
					  "Too much data for OAEP encoding"))
      (let* ((ps (make-bytevector ps-len 0))
	     (db (bytevector-append lhash ps #vu8(#x01) data))
	     (seed (random-generator:read-random-bytes prng hlen))
	     (db-mask (mgf seed (- k hlen 1) mgf-sha))
	     (masked-db (bytevector-xor! db 0 db-mask 0 (bytevector-length db)))
	     (seed-mask (mgf masked-db hlen mgf-sha))
	     (masked-seed (bytevector-xor! seed 0 seed-mask 0 hlen)))
	(bytevector-append #vu8(#x00) masked-seed masked-db)))

    (define (decode data state)
      (define k
	(asymmetric-scheme-descriptor:get-block-size descriptor state))
      (define db-len (- k hlen 1))
      (define (parse-em data)
	(let ((ms (make-bytevector hlen))
	      (db (make-bytevector db-len)))
	  (bytevector-copy! data 1 ms 0 hlen)
	  (bytevector-copy! data (+ hlen 1) db 0 db-len)
	  (values (bytevector-u8-ref data 0) ms db)))
      (define (parse-db db)
	(define (find-ps-end db)
	  (do ((i hlen (+ i 1)))
	      ((= (bytevector-u8-ref db i) #x01) i)))
	(let* ((ps-end (find-ps-end db))
	       (Y (make-bytevector hlen))
	       (ps-len (- ps-end hlen))
	       (ps (make-bytevector ps-len))
	       (M (make-bytevector (- db-len hlen ps-len 1))))
	  (bytevector-copy! db 0 Y 0 hlen)
	  (bytevector-copy! db hlen ps 0 ps-len)
	  (bytevector-copy! db (+ hlen ps-len 1) M 0 (bytevector-length M))
	  (values Y ps (bytevector-u8-ref db ps-end) M)))

      (when (> (bytevector-length data) k)
	(springkussen-assertion-violation 'oaep-decoding
					  "Too much data for OAEP encoding"))
      (let-values (((Y masked-seed masked-db) (parse-em data)))
	(let* ((seed-mask (mgf masked-db hlen mgf-sha))
	       (seed (bytevector-xor! masked-seed 0 seed-mask 0
				      (bytevector-length masked-seed)))
	       (db-mask (mgf seed db-len mgf-sha))
	       (db (bytevector-xor! masked-db 0 db-mask 0
				    (bytevector-length masked-db))))
	  (let-values (((lhash-dash ps one M) (parse-db db)))
	    (unless (and (bytevector-safe=? lhash lhash-dash)
			 (zero? Y)
			 (= one #x01))
	      (springkussen-error 'oaep-decoding "Invalid OAEP encoding"))
	    M))))
    (values encode decode))))

(define pkcs1-v1.5-encoding
  (case-lambda
   ((descriptor) (pkcs1-v1.5-encoding descriptor #f))
   ((descriptor param)
    (define prng
      (encoding-parameter-random-generator param default-random-generator))
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
