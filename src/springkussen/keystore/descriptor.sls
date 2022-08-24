;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/keystore/descriptor.sls - Keystore descriptor
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
(library (springkussen keystore descriptor)
    (export keystore-descriptor?
	    keystore-descriptor-builder

	    keystore-key-operation
	    keystore-certificate-operation

	    keystore-descriptor:load
	    keystore-descriptor:store
	    keystore-descriptor:ref-private-key
	    keystore-descriptor:set-private-key!
	    keystore-descriptor:ref-secret-key
	    keystore-descriptor:set-secret-key!
	    keystore-descriptor:ref-certificate
	    keystore-descriptor:set-certificate!
	    keystore-descriptor:ref-certificate-chain)
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen misc record))

(define-enumeration keystore-key-operation (get set)
  keystore-key-operations)

(define-enumeration keystore-certificate-operation (get set chain)
  keystore-certificate-operations)

(define-record-type keystore-descriptor
  (fields loader
	  storer
	  private-key-op
	  cert-op
	  secret-key-op
	  contains))
(define-syntax keystore-descriptor-builder
  (make-record-builder keystore-descriptor))

(define (keystore-descriptor:load desc bv)
  ((keystore-descriptor-loader desc) bv))

(define (keystore-descriptor:store desc ks out)
  ((keystore-descriptor-storer desc) ks out))

(define (keystore-descriptor:ref-private-key desc ks alias)
  ((keystore-descriptor-private-key-op desc) 'get ks alias))

(define (keystore-descriptor:set-private-key! desc ks alias key password certs)
  ((keystore-descriptor-private-key-op desc) 'set ks alias key password certs))

(define (keystore-descriptor:ref-secret-key desc ks alias)
  (let ((op (keystore-descriptor-secret-key-op desc)))
    (if op
	(op 'get ks alias)
	(springkussen-assertion-violation 'keystore-descriptor:ref-secret-key
					  "Not supported"))))

(define (keystore-descriptor:set-secret-key! desc ks alias key password)
  (let ((op (keystore-descriptor-secret-key-op desc)))
    (if op
	(op 'set ks alias key password)
	(springkussen-assertion-violation 'keystore-descriptor:set-secret-key!
					  "Not supported"))))

(define (keystore-descriptor:ref-certificate desc ks alias)
  ((keystore-descriptor-cert-op desc) 'get ks alias))

(define (keystore-descriptor:set-certificate! desc ks alias key cert)
  ((keystore-descriptor-cert-op desc) 'set ks alias key cert))

(define (keystore-descriptor:ref-certificate-chain desc ks alias)
  ((keystore-descriptor-cert-op desc) 'chain ks alias))

(define (keystore-descriptor:contains? desc ks alias)
  (let ((op (keystore-descriptor-contains desc)))
    (if op
	(op ks alias)
	;; Default, we don't check secret key
	(or (keystore-descriptor:ref-private-key desc ks alias)
	    (keystore-descriptor:ref-certificate desc ks alias)))))
)
