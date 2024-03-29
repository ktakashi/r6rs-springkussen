;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/asymmetric/key.sls - Asymmetric key
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
(library (springkussen cipher asymmetric key)
    (export (rename (asymmetric-key <asymmetric-key>)
		    (public-key <public-key>)
		    (private-key <private-key>))
	    asymmetric-key?

	    asymmetric-key-operation? make-asymmetric-key-operation
	    (rename (asymmetric-key-operation <asymmetric-key-operation>))
	    asymmetric-key:import-key
	    asymmetric-key:export-key
	    
	    public-key?
	    private-key?

	    key-pair-factory? (rename (key-pair-factory <key-pair-factory>))
	    make-key-pair-factory
	    key-pair-factory:generate-key-pair
	    
	    key-pair? make-key-pair
	    key-pair-private key-pair-public

	    define-key-parameter
	    )
    (import (rnrs)
	    (springkussen cipher key)
	    (springkussen conditions))

(define-record-type asymmetric-key 
  (parent <key>))

(define-record-type public-key 
  (parent asymmetric-key))

(define-record-type private-key 
  (parent asymmetric-key))

(define-record-type key-pair
  (fields private public))

(define-record-type key-pair-factory
  (fields key-pair-generator))

(define-record-type asymmetric-key-operation
  (fields importer
	  exporter))

(define (asymmetric-key:import-key operation bv)
  ((asymmetric-key-operation-importer operation) bv))

(define (asymmetric-key:export-key operation key)
  ((asymmetric-key-operation-exporter operation) key))

(define key-pair-factory:generate-key-pair
  (case-lambda
   ((kpf) (key-pair-factory:generate-key-pair kpf #f))
   ((kpf parameter)
    (unless (key-pair-factory? kpf)
      (springkussen-assertion-violation 'key-pair-factory:generate-key-pair
					"Key pair factory is required" kpf))
    ((key-pair-factory-key-pair-generator kpf) parameter))))

;; Temporary solution
(define-syntax define-key-parameter (make-define-key-parameter))
)

