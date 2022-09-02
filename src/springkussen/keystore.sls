;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/keystore.sls - Keystore APIs
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
(library (springkussen keystore)
    (export pkcs12-keystore? pkcs12-keystore-builder
	    read-pkcs12-keystore
	    bytevector->pkcs12-keystore
	    write-pkcs12-keystore
	    pkcs12-keystore->bytevector

	    pkcs12-entry-type pkcs12-entry-types
	    
	    pkcs12-keystore-private-key-ref
	    pkcs12-keystore-private-key-set!
	    pkcs12-keystore-private-key-delete!
	    pkcs12-keystore-certificate-ref
	    pkcs12-keystore-certificate-set!
	    pkcs12-keystore-certificate-delete!
	    pkcs12-keystore-certificate-revocation-list-ref
	    pkcs12-keystore-certificate-revocation-list-set!
	    pkcs12-keystore-certificate-revocation-list-delete!
	    pkcs12-keystore-secret-key-ref
	    pkcs12-keystore-secret-key-set!
	    pkcs12-keystore-secret-key-delete!

	    pkcs12-keystore-contains?
	    pkcs12-keystore-alias-entries
	    pkcs12-keystore-all-aliases
	    
	    pkcs12-keystore-add-attribute!
	    pkcs12-keystore-delete-entry!
	    
	    pkcs12-mac-descriptor? make-pkcs12-mac-descriptor

	    pkcs12-attribute?
	    ;; For Java trusted cert...
	    *java-trusted-certificate-attribute*

	    ;; For whatever the reason...
	    *pkcs12-pbe/sha1-and-des3-cbc*
	    *pkcs12-pbe/sha1-and-des2-cbc*
	    *pkcs12-pbe/sha1-and-rc2-128-cbc*
	    *pkcs12-pbe/sha1-and-rc2-40-cbc*
	    make-pbe-encryption-algorithm

	    *pbes2-aes128-cbc-pad/hmac-sha256*
	    *pbes2-aes192-cbc-pad/hmac-sha256*
	    *pbes2-aes256-cbc-pad/hmac-sha256*
	    make-pbes2-encryption-algorithm)
    (import (springkussen keystore pfx)))
