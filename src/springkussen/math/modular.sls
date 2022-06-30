;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/math/modular.sls - Modular arithmetic
;;;
;;;  Copyright (c) 2022 Takashi Kato. All rights reserved.
;;;
;;;  Redistribution and use in source and binary forms, with or without
;;;  modification, are permitted provided that the following conditions
;;;  are met:
;;;
;;;  1. Redistributions of source code must retain the above copyright
;;;     notice, this list of conditions and the following disclaimer.
;;;
;;;  2. Redistributions in binary form must reproduce the above copyright
;;;     notice, this list of conditions and the following disclaimer in the
;;;     documentation and/or other materials provided with the distribution.
;;;
;;;  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;;;  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;;;  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;;;  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;;;  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;;;  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
;;;  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;;;  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;;;  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;;  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;;  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#!r6rs
(library (springkussen math modular)
    (export mod-inverse
	    mod-expt
	    mod-add
	    mod-sub
	    mod-mul
	    mod-div
	    mod-square
	    mod-negate
	    mod-sqrt)
    (import (rnrs))

(define (mod-inverse x m)
  (let loop ((u1 1) (u3 x) (v1 0) (v3 m) (neg? #f))
    (if (= v3 0)
	(if neg? (- m u1) u1)
	(let* ((t3 (mod u3 v3))
	       (q (div u3 v3))
	       (w (* q v1))
	       (t1 (+ u1 w)))
	  (loop v1 v3 t1 t3 (not neg?))))))

;; https://en.wikipedia.org/wiki/Modular_exponentiation#Pseudocode
(define (mod-expt x e m)
  (when (negative? m)
    (assertion-violation 'mod-expt
			 "Modular must be a positive exact integer" m))
  (if (= m 1)
      0
      (let ((invert? (negative? e)))
	(let loop ((r 1) (b (mod x m)) (e (abs e)))
	  (if (<= e 0)
	      (if invert? (mod-inverse r m) r)
	      (let ((r (if (= (mod e 2) 1) (mod (* r b) m) r)))
		(loop r (mod (* b b) m) (bitwise-arithmetic-shift e -1))))))))

;; modular arithmetic
;; a + b (mod p)
(define (mod-add a b p) (mod (+ a b) p))
;; a - b (mod p)
(define (mod-sub a b p) (mod (- (+ a p) b) p))
;; a * b (mod p)
(define (mod-mul a b p) (mod (* a b) p))
;;(define (mod-mul a b p) (* (mod a p) (mod b p)))
;; a / b (mod p)
(define (mod-div a b p) (mod (* a (mod-inverse b p)) p))
;; a^2 (mod p)
(define (mod-square a p) (mod-expt a 2 p))
;; -a (mod p)
(define (mod-negate a p) (mod (- p a) p))

;; This only works for prime number (for now)
;; https://www.rieselprime.de/ziki/Modular_square_root
(define (mod-sqrt x p)
  (define (sqrt4k3 x p) (mod-expt x (div (+ p 1) 4) p))
  (define (sqrt8k5 x p)
    (let ((y (mod-expt x (div (+ p 3) 8) p)))
      (if (= (mod (* y y) p) (mod x p))
	  y
	  (let ((z (mod-expt 2 (div (- p 1) 4) p)))
	    (mod (* y z) p)))))
  (let ((y (mod (cond ((= (mod p 4) 3) (sqrt4k3 x p))
		      ((= (mod p 8) 5) (sqrt8k5 x p))
		      ;; TODO 8m+1
		      (else
		       (assertion-violation 'mod-sqrt "Not implemented")))
		p)))
    (and (= x (mod-square y p)) y)))

)
