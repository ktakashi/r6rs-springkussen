;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/digest/sha512.sls - SHA-512 family operations
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
(library (springkussen digest sha512)
    (export sha512-descriptor
	    sha384-descriptor
	    sha512/224-descriptor
	    sha512/256-descriptor
	    )
    (import (rnrs)
	    (springkussen digest descriptor)
	    (springkussen conditions)
	    (springkussen misc bitwise))

(define-record-type sha512
  (parent <block-digest-state>)
  (protocol (lambda (n)
	      (lambda ()
		((n 128 (vector #x6a09e667f3bcc908
				#xbb67ae8584caa73b
				#x3c6ef372fe94f82b
				#xa54ff53a5f1d36f1
				#x510e527fade682d1
				#x9b05688c2b3e6c1f
				#x1f83d9abfb41bd6b
				#x5be0cd19137e2179)))))))

(define-record-type sha384
  (parent <block-digest-state>)
  (protocol (lambda (n)
	      (lambda ()
		((n 128 (vector #xcbbb9d5dc1059ed8
				#x629a292a367cd507
				#x9159015a3070dd17
				#x152fecd8f70e5939
				#x67332667ffc00b31
				#x8eb44a8768581511
				#xdb0c2e0d64f98fa7
				#x47b5481dbefa4fa4)))))))

(define-record-type sha512/224
  (parent <block-digest-state>)
  (protocol (lambda (n)
	      (lambda ()
		((n 128 (vector #x8C3D37C819544DA2
				#x73E1996689DCD4D6
				#x1DFAB7AE32FF9C82
				#x679DD514582F9FCF
				#x0F6D2B697BD44DA8
				#x77E36F7304C48942
				#x3F9D85A86A1D36C8
				#x1112E6AD91D692A1)))))))

(define-record-type sha512/256
  (parent <block-digest-state>)
  (protocol (lambda (n)
	      (lambda ()
		((n 128 (vector #x22312194FC2BF72C
				#x9F555FA3C84C64C2
				#x2393B86B6F53B151
				#x963877195940EABD
				#x96283EE2A88EFFE3
				#xBE5E1E2553863992
				#x2B0199FC2C85B8AA
				#x0EB72DDC81C52CA2)))))))

(define K '#(#x428a2f98d728ae22 #x7137449123ef65cd 
	     #xb5c0fbcfec4d3b2f #xe9b5dba58189dbbc
	     #x3956c25bf348b538 #x59f111f1b605d019 
	     #x923f82a4af194f9b #xab1c5ed5da6d8118
	     #xd807aa98a3030242 #x12835b0145706fbe 
	     #x243185be4ee4b28c #x550c7dc3d5ffb4e2
	     #x72be5d74f27b896f #x80deb1fe3b1696b1 
	     #x9bdc06a725c71235 #xc19bf174cf692694
	     #xe49b69c19ef14ad2 #xefbe4786384f25e3 
	     #x0fc19dc68b8cd5b5 #x240ca1cc77ac9c65
	     #x2de92c6f592b0275 #x4a7484aa6ea6e483 
	     #x5cb0a9dcbd41fbd4 #x76f988da831153b5
	     #x983e5152ee66dfab #xa831c66d2db43210 
	     #xb00327c898fb213f #xbf597fc7beef0ee4
	     #xc6e00bf33da88fc2 #xd5a79147930aa725 
	     #x06ca6351e003826f #x142929670a0e6e70
	     #x27b70a8546d22ffc #x2e1b21385c26c926 
	     #x4d2c6dfc5ac42aed #x53380d139d95b3df
	     #x650a73548baf63de #x766a0abb3c77b2a8 
	     #x81c2c92e47edaee6 #x92722c851482353b
	     #xa2bfe8a14cf10364 #xa81a664bbc423001
	     #xc24b8b70d0f89791 #xc76c51a30654be30
	     #xd192e819d6ef5218 #xd69906245565a910 
	     #xf40e35855771202a #x106aa07032bbd1b8
	     #x19a4c116b8d2d0c8 #x1e376c085141ab53 
	     #x2748774cdf8eeb99 #x34b0bcb5e19b48a8
	     #x391c0cb3c5c95a63 #x4ed8aa4ae3418acb 
	     #x5b9cca4f7763e373 #x682e6ff3d6b2b8a3
	     #x748f82ee5defb2fc #x78a5636f43172f60 
	     #x84c87814a1f0ab72 #x8cc702081a6439ec
	     #x90befffa23631e28 #xa4506cebde82bde9 
	     #xbef9a3f7b2c67915 #xc67178f2e372532b
	     #xca273eceea26619c #xd186b8c721c0c207 
	     #xeada7dd6cde0eb1e #xf57d4f7fee6ed178
	     #x06f067aa72176fba #x0a637dc5a2c898a6 
	     #x113f9804bef90dae #x1b710b35131c471b
	     #x28db77f523047d84 #x32caab7b40c72493 
	     #x3c9ebe0a15c9bebc #x431d67c49c100d4c
	     #x4cc5d4becb3e42b6 #x597f299cfc657e2a 
	     #x5fcb6fab3ad6faec #x6c44198c4a475817))

(define (sha512-compress sha512 buffer start)
  (define (ch x y z) (bitwise-xor z (bitwise-and x (bitwise-xor y z))))
  (define (maj x y z) (bitwise-ior (bitwise-and (bitwise-ior x y) z)
				   (bitwise-and x y)))
  (define S ror64c)
  (define (R x n)
    (bitwise-arithmetic-shift-right (bitwise-and x #xFFFFFFFFFFFFFFFF) n))
  (define (sigma0 x) (bitwise-xor (S x 28) (S x 34) (S x 39)))
  (define (sigma1 x) (bitwise-xor (S x 14) (S x 18) (S x 41)))
  (define (gamma0 x) (bitwise-xor (S x  1) (S x  8) (R x  7)))
  (define (gamma1 x) (bitwise-xor (S x 19) (S x 61) (R x  6)))
  (define (setup-w buffer)
    (define (fill w)
      (do ((i 16 (+ i 1)))
	  ((= i 80) w)
	(let ((v (+ (gamma1 (vector-ref w (- i 2)))
		    (vector-ref w (- i 7))
		    (gamma0 (vector-ref w (- i 15)))
		    (vector-ref w (- i 16)))))
	  (vector-set! w i v))))
    (let ((w (make-vector 80)))
      (do ((i 0 (+ i 1)))
	  ((= i 16) (fill w))
	(vector-set! w i (load64h buffer (+ start (* i 8)))))))
  (define (feedback state S0 S1 S2 S3 S4 S5 S6 S7)
    (vector-set! state 0 (+ (vector-ref state 0) S0))
    (vector-set! state 1 (+ (vector-ref state 1) S1))
    (vector-set! state 2 (+ (vector-ref state 2) S2))
    (vector-set! state 3 (+ (vector-ref state 3) S3))
    (vector-set! state 4 (+ (vector-ref state 4) S4))
    (vector-set! state 5 (+ (vector-ref state 5) S5))
    (vector-set! state 6 (+ (vector-ref state 6) S6))
    (vector-set! state 7 (+ (vector-ref state 7) S7)))
  						  
  (define state (block-digest-state-state sha512))
  (define W (setup-w buffer))
  (let loop ((i 0)
	     (S0 (vector-ref state 0))
	     (S1 (vector-ref state 1))
	     (S2 (vector-ref state 2))
	     (S3 (vector-ref state 3))
	     (S4 (vector-ref state 4))
	     (S5 (vector-ref state 5))
	     (S6 (vector-ref state 6))
	     (S7 (vector-ref state 7)))
    (if (= i 80)
	(feedback state S0 S1 S2 S3 S4 S5 S6 S7)
	(let ((t0 (+ S7 (sigma1 S4) (ch S4 S5 S6)
		     (vector-ref K i) (vector-ref W i)))
	      (t1 (+ (sigma0 S0) (maj S0 S1 S2))))
	  (loop (+ i 1) (+ t0 t1) S0 S1 S2 (+ S3 t0) S4 S5 S6)))))

(define sha512-process (make-block-digest-processor sha512-compress 128))

(define sha512-done
  (make-block-digest-finalizer sha512-compress 128 store64h 64))

(define sha512-descriptor
  (digest-descriptor-builder
   (name "SHA-512")
   (digest-size 64)
   (oid "2.16.840.1.101.3.4.2.3")
   (initializer make-sha512)
   (processor sha512-process)
   (finalizer sha512-done)))

(define sha384-done
  (make-block-digest-finalizer sha512-compress 128 store64h 48))

(define sha384-descriptor
  (digest-descriptor-builder
   (name "SHA-384")
   (digest-size 48)
   (oid "2.16.840.1.101.3.4.2.2")
   (initializer make-sha384)
   (processor sha512-process)
   (finalizer sha384-done)))

;; make-block-digest-finalizer only works when the digest-size is multiple of 8
;; So wrap a bit
(define sha512/224-done
  (let ((dummy-done
	 (make-block-digest-finalizer sha512-compress 128 store64h 32)))
    (lambda (state out pos)
      (let ((buf (make-bytevector 32)))
	(dummy-done state buf 0)
	(bytevector-copy! buf 0 out pos 28)
	out))))
(define sha512/224-descriptor
  (digest-descriptor-builder
   (name "SHA-512/224")
   (digest-size 28)
   (oid "2.16.840.1.101.3.4.2.5")
   (initializer make-sha512/224)
   (processor sha512-process)
   (finalizer sha512/224-done)))

(define sha512/256-done
  (make-block-digest-finalizer sha512-compress 128 store64h 32))
(define sha512/256-descriptor
  (digest-descriptor-builder
   (name "SHA-512/256")
   (digest-size 32)
   (oid "2.16.840.1.101.3.4.2.6")
   (initializer make-sha512/256)
   (processor sha512-process)
   (finalizer sha512/256-done)))

)
