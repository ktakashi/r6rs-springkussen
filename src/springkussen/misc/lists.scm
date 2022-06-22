;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/misc/lists.sls - Misc list operations
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

;; To avoid using SRFI-1, for Chez mainly...
#!r6rs
(library (springkussen misc lists)
    (export lset-union lset-difference)
    (import (rnrs))

(define (fold1 proc seed lst1)
  (let loop ((lis lst1) (knil seed))
    (if (null? lis)
	knil
	(loop (cdr lis) (proc (car lis) knil)))))


(define (reduce f ridentity lis)
  (unless (procedure? f)
    (assertion-violation
     'reduce "Procedure requried for the first argument" f))
  (if (null? lis)
      ridentity
      (fold1 f (car lis) (cdr lis))))

(define (lset-union = . lists)
  (unless (procedure? =)
    (assertion-violation
     'lset-union "Procedure required for the first argument" =))
  (reduce (lambda (lis ans)     ; Compute ANS + LIS.
	    (cond ((null? lis) ans) ; Don't copy any lists
		  ((null? ans) lis)     ; if we don't have to.
		  ((eq? lis ans) ans)
		  (else
		   (fold1 (lambda (elt ans)
			    (if (exists (lambda (x) (= x elt)) ans)
				ans
				(cons elt ans)))
			  ans lis))))
	  '() lists))

(define (lset-difference = lis1 . lists)
  (unless (procedure? =)
    (assertion-violation 'lset-difference
			 "Procedure required for the first argument" =))
  (let ((lists (filter pair? lists)))   ; Throw out empty lists.
    (cond ((null? lists)     lis1)  ; Short cut
	  ((memq lis1 lists) '())   ; Short cut
	  (else (filter (lambda (x)
			  (for-all (lambda (lis) (not (member= x lis =)))
				   lists))
			lis1)))))


(define (member= x lis . =)
  (if (null? =)
      (member= x lis equal?)
      (find-tail (lambda (y) ((car =) x y)) lis)))

(define (find-tail pred list)
  (unless (procedure? pred)
    (assertion-violation 'find-tail
			 "Procedure required for the second argument" pred))
  (let lp ((list list))
    (and (not (null? list))
	 (if (pred (car list))
	     list
	     (lp (cdr list))))))

)

