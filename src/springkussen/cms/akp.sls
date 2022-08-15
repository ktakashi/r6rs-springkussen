;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cms/akp.sls - Asymmetric Key Packages
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

;; ref:
;;  - https://datatracker.ietf.org/doc/html/rfc5958
;;  - https://datatracker.ietf.org/doc/html/rfc5208 (obsolated)
#!r6rs
(library (springkussen cms akp)
    (export cms-one-asymmetric-key? make-cms-one-asymmetric-key
	    cms-one-asymmetric-key-version
	    cms-one-asymmetric-key-private-key-algorithm
	    cms-one-asymmetric-key-private-key
	    cms-one-asymmetric-key-attributes
	    cms-one-asymmetric-key-public-key
	    
	    make-cms-private-key-info
	    cms-private-key-info?)
    (import (rnrs)
	    (springkussen asn1)
	    (springkussen conditions)
	    (springkussen misc lambda)
	    (springkussen x509 types)
	    (springkussen cms types))

(define-record-type cms-one-asymmetric-key
  (parent <asn1-encodable-object>)
  (fields version private-key-algorithm private-key attributes public-key)
  (protocol (lambda (n)
	      (lambda/typed ((version der-integer?)
			     (private-key-algorithm algorithma-identifier?)
			     (private-key der-octet-string?)
			     (attributes (or #f (der-set-of? cms-attribute?)))
			     (public-key (or #f der-bit-string?)))
	       (when (and public-key (< (der-integer-value version) 2))
		 (springkussen-assertion-violation 'make-cms-one-asymmetric-key
		   "Invalid version, must be 2 or higher" version))
	       ((n cms-one-asymmetric-key->asn1-object)
		version private-key-algorithm private-key
		attributes public-key)))))
(define (cms-one-asymmetric-key->asn1-object self)
  (define (->tagged o tag)
    (and o (make-der-tagged-object tag #f o)))
  (make-der-sequence
   (filter values
	   (list (cms-one-asymmetric-key-version self)
		 (cms-one-asymmetric-key-private-key-algorithm self)
		 (cms-one-asymmetric-key-private-key self)
		 (->tagged (cms-one-asymmetric-key-attributes self) 0)
		 (->tagged (cms-one-asymmetric-key-public-key self) 1)))))

;; RFC 5208 compatible thing
(define/typed (make-cms-private-key-info
	       (version der-integer?)
	       (private-key-algorithm algorithma-identifier?)
	       (private-key der-octet-string?)
	       (attributes (or #f (der-set-of? cms-attribute?))))
  (unless (zero? (der-integer-value version))
    (springkussen-assertion-violation 'make-cms-private-key-info
				      "Invalid version, must be 0" version))
  (make-cms-one-asymmetric-key vevrsion
			       private-key-algorithm
			       private-key
			       attributes
			       #f))
(define (cms-private-key-info? obj)
  (and (cms-one-asymmetric-key? obj)
       (zero? (cms-one-asymmetric-key-version obj))))

)
