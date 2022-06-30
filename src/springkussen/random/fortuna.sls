;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/random/fortuna.sls - Fortuna PRNG
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
(library (springkussen random fortuna)
    (export fortuna-descriptor)
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen random descriptor)
	    (springkussen cipher symmetric scheme descriptor)
	    (springkussen cipher symmetric scheme aes)
	    (springkussen digest descriptor)
	    (springkussen digest sha256))

(define-record-type fortuna-state
  (parent <prng-state>)
  (fields pool
	  (mutable skey)
	  K
	  IV
	  (mutable pool-index)
	  (mutable pool0-length)
	  (mutable wd)
	  (mutable reset-count))
  (protocol (lambda (p)
	      (lambda ()
		(let* ((K (make-bytevector 32 0))
		       (skey (symmetric-scheme-descriptor:setup
			      aes-descriptor K 0)))
		  ((p)
		   (make-vector 32)
		   skey
		   K
		   (make-bytevector 16 0)
		   0 0 0 0))))))

(define *fortuna-wd* 10)

(define (fortuna-start)
  (define (setup-pool state)
    (let ((pool (fortuna-state-pool state)))
      (do ((i 0 (+ i 1)) (len (vector-length pool)))
	  ((= i len) state)
	(vector-set! pool i (digest-descriptor:init sha256-descriptor)))))
  (define state (make-fortuna-state))
  (setup-pool state))

(define (fortuna-add-entropy! state in start end)
  (let ((end (if (> (- start end) 32) (+ start 32) end))
	(pool (fortuna-state-pool state))
	(pool-index (fortuna-state-pool-index state))
	(tmp (make-bytevector 2 0)))
    (bytevector-u8-set! tmp 1 (- end start))
    (digest-descriptor:process! sha256-descriptor (vector-ref pool pool-index)
				tmp)
    (digest-descriptor:process! sha256-descriptor (vector-ref pool pool-index)
				in start end)
    (when (zero? pool-index)
      (let ((p0-len (fortuna-state-pool0-length state)))
	(fortuna-state-pool0-length-set! state (+ p0-len (- end start)))))
    (if (= pool-index (- (vector-length pool)))
	(fortuna-state-pool-index-set! state 0)
	(fortuna-state-pool-index-set! state (+ pool-index 1)))))

(define (fortuna-ready state)
  (fortuna-reseed! state)
  (prng-state-ready?-set! state #t))

(define (fortuna-read state out start len)
  (define (encrypt state out s)
    (define skey (fortuna-state-skey state))
    (define iv (fortuna-state-IV state))
    (symmetric-scheme-descriptor:encrypt aes-descriptor skey iv 0 out s)
    (fortuna-update-iv state))

  (define wd (fortuna-state-wd state))
  (define p0-len (fortuna-state-pool0-length state))
  (when (or (= (+ wd 1) *fortuna-wd*) (>= p0-len 64))
    (fortuna-reseed! state))
  ;; generate random
  (do ((l len (- l 16)) (s start (+ s 16)))
      ((< l 16)
       (when (> l 0)
	 (let ((tmp (make-bytevector 16)))
	   (encrypt state tmp 0)
	   (bytevector-copy! tmp 0 out s l))))
    (encrypt state out s))
  ;; generate new key
  (let ((k (fortuna-state-K state)))
    (encrypt state k 0)
    (encrypt state k 16)
    (fortuna-state-skey-set! state
     (symmetric-scheme-descriptor:setup aes-descriptor k 0)))
  len)

(define (fortuna-done state)
  (prng-state-ready?-set! state #f)
  (let ((tmp (make-bytevector 32)))
    (vector-for-each (lambda (s)
		       (digest-descriptor:done! sha256-descriptor s tmp))
		     (fortuna-state-pool state))))

(define (fortuna-export state out s)
  (springkussen-assertion-violation 'fortuna "Not yet"))

(define (fortuna-import state in s len)
  (springkussen-assertion-violation 'fortuna "Not yet"))

(define fortuna-descriptor
  (random-descriptor-builder
   (name "Fortuna")
   (export-size (* 32 32))
   (starter fortuna-start)
   (entropy-updater fortuna-add-entropy!)
   (initializer fortuna-ready)
   (reader fortuna-read)
   (finalizer fortuna-done)
   (importer fortuna-import)
   (exporter fortuna-export)))

(define (fortuna-update-iv state)
  (do ((iv (fortuna-state-IV state))
       (x 0 (+ x 1)))
      ((or (= x 16) (not (zero? (bytevector-u8-ref iv x)))))
    (bytevector-u8-set! iv x
			(bitwise-and (+ (bytevector-u8-ref iv x) 1) #xFF))))

(define (fortuna-reseed! state)
  (define sha256d sha256-descriptor)
  (define md (digest-descriptor:init sha256d))
  (define reset-count (fortuna-state-reset-count state))
  (define pool (fortuna-state-pool state))

  (fortuna-state-reset-count-set! state (+ reset-count 1))
  (digest-descriptor:process! sha256d md (fortuna-state-K state))
  (do ((x 0 (+ x 1)) (l (vector-length pool))
       (rc (fortuna-state-reset-count state))
       (tmp (make-bytevector 32)))
      ((or (= x l)
	   (and (not (zero? x))
		(not (zero? (bitwise-and
			     (bitwise-arithmetic-shift rc (- x 1)) 1))))))
    (digest-descriptor:done! sha256d (vector-ref pool x) tmp)
    (digest-descriptor:process! sha256d md tmp)
    (vector-set! pool x (digest-descriptor:init sha256d)))
  (let ((k (fortuna-state-K state)))
    (digest-descriptor:done! sha256d md k)
    (let ((skey (symmetric-scheme-descriptor:setup aes-descriptor k 0)))
      (fortuna-state-skey-set! state skey))
    (fortuna-update-iv state)))
)
