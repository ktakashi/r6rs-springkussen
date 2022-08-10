;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/symmetric/scheme/rc2.sls - RC2 operation
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
(library (springkussen cipher symmetric scheme rc2)
    (export rc2-descriptor)
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen cipher symmetric scheme descriptor)
	    (springkussen misc bitwise)
	    (springkussen misc vectors))


(define-record-type rc2-key
  (fields xkey)
  (protocol (lambda (p)
	      (lambda (xkey)
		(p xkey)))))
(define << bitwise-arithmetic-shift)
(define >> bitwise-arithmetic-shift-right)
(define u8ref bytevector-u8-ref)
(define (rc2-setup key round)
  (define keylen (bytevector-length key))
  (unless (or (zero? round) (= round 16))
    (springkussen-assertion-violation 'setup "invalid round" round))
  (let ((tmp (make-bytevector 128))
	(xkey (make-vector 64)))
    (bytevector-copy! key 0 tmp 0 keylen)
    ;; expand input key to 128 bytes
    (when (< keylen 128)
      (do ((i keylen (+ i 1)))
	  ((= i 128))
	(let ((v (bitwise-and (+ (u8ref tmp (- i 1))
				 (u8ref tmp (- i keylen))) #xFF)))
	  (bytevector-u8-set! tmp i (u8ref permute v)))))
    ;; reduce effective key size to bits
    (let* ((bits (<< keylen 3))
	   (T8 (>> (+ bits 7) 3))
	   (TM (>> 255 (bitwise-and 7 (- bits))))
	   (i (- 128 T8))
	   (tv (u8ref tmp i)))
      (bytevector-u8-set! tmp i (u8ref permute (bitwise-and tv TM)))
      (do ((i (- 127 T8) (- i 1)))
	  ((< i 0))
	(let ((v (u8ref permute (bitwise-xor (u8ref tmp (+ i 1))
					     (u8ref tmp (+ i T8))))))
	  (bytevector-u8-set! tmp i v))))
    ;; copy to xkay in little endian
    (do ((i 0 (+ i 1)))
	((= i 64) (make-rc2-key xkey))
      (vector-set! xkey i
		   (bytevector-u16-ref tmp (* i 2) (endianness little))))))

(define & bitwise-and)
(define ~ bitwise-not)
(define (u16 v) (& v #xFFFF))
(define (rc2-encrypt pt ps ct cs key)
  (define xkey (rc2-key-xkey key))
  (define (store-ct x10 x32 x54 x76)
    (bytevector-u16-set! ct    cs    (u16 x10) (endianness little))
    (bytevector-u16-set! ct (+ cs 2) (u16 x32) (endianness little))
    (bytevector-u16-set! ct (+ cs 4) (u16 x54) (endianness little))
    (bytevector-u16-set! ct (+ cs 6) (u16 x76) (endianness little)))
  (let loop ((x10 (bytevector-u16-ref pt    ps    (endianness little)))
	     (x32 (bytevector-u16-ref pt (+ ps 2) (endianness little)))
	     (x54 (bytevector-u16-ref pt (+ ps 4) (endianness little)))
	     (x76 (bytevector-u16-ref pt (+ ps 6) (endianness little)))
	     (i 0))
    (if (= i 16)
	(store-ct x10 x32 x54 x76)
	(let* ((x10 (u16 (+ x10 (& x32 (~ x76)) (& x54 x76)
			    (vector-ref xkey (+ (* 4 i) 0)))))
	       (x10 (bitwise-ior (<< x10 1) (>> x10 15)))
	       (x32 (u16 (+ x32 (& x54 (~ x10)) (& x76 x10)
			    (vector-ref xkey (+ (* 4 i) 1)))))
	       (x32 (bitwise-ior (<< x32 2) (>> x32 14)))
	       (x54 (u16 (+ x54 (& x76 (~ x32)) (& x10 x32)
			    (vector-ref xkey (+ (* 4 i) 2)))))
	       (x54 (bitwise-ior (<< x54 3) (>> x54 13)))
	       (x76 (u16 (+ x76 (& x10 (~ x54)) (& x32 x54)
			    (vector-ref xkey (+ (* 4 i) 3)))))
	       (x76 (bitwise-ior (<< x76 5) (>> x76 11))))
	  (if (or (= i 4) (= i 10))
	      (let* ((x10 (u16 (+ x10 (vector-ref xkey (& x76 63)))))
		     (x32 (u16 (+ x32 (vector-ref xkey (& x10 63)))))
		     (x54 (u16 (+ x54 (vector-ref xkey (& x32 63)))))
		     (x76 (u16 (+ x76 (vector-ref xkey (& x54 63))))))
		(loop x10 x32 x54 x76 (+ i 1)))
	      (loop x10 x32 x54 x76 (+ i 1))))))
  8)

(define (rc2-decrypt ct cs pt ps key)
  (define xkey (rc2-key-xkey key))
  (define (store-pt x10 x32 x54 x76)
    (bytevector-u16-set! pt    ps    (u16 x10) (endianness little))
    (bytevector-u16-set! pt (+ ps 2) (u16 x32) (endianness little))
    (bytevector-u16-set! pt (+ ps 4) (u16 x54) (endianness little))
    (bytevector-u16-set! pt (+ ps 6) (u16 x76) (endianness little)))
  (let loop ((x10 (bytevector-u16-ref ct    cs    (endianness little)))
	     (x32 (bytevector-u16-ref ct (+ cs 2) (endianness little)))
	     (x54 (bytevector-u16-ref ct (+ cs 4) (endianness little)))
	     (x76 (bytevector-u16-ref ct (+ cs 6) (endianness little)))
	     (i 15))
    (if (< i 0)
	(store-pt x10 x32 x54 x76)
	(let-values (((x10 x32 x54 x76)
		      (if (or (= i 4) (= i 10))
			  (let* ((x76
				  (u16 (- x76 (vector-ref xkey (& x54 63)))))
				 (x54
				  (u16 (- x54 (vector-ref xkey (& x32 63)))))
				 (x32
				  (u16 (- x32 (vector-ref xkey (& x10 63)))))
				 (x10
				  (u16 (- x10 (vector-ref xkey (& x76 63))))))
			    (values x10 x32 x54 x76))
			  (values x10 x32 x54 x76))))
	  (let* ((x76 (bitwise-ior (<< x76 11) (>> x76 5)))
		 (x76 (u16 (- x76 (+ (& x10 (~ x54)) (& x32 x54)
				     (vector-ref xkey (+ (* 4 i) 3))))))
		 (x54 (bitwise-ior (<< x54 13) (>> x54 3)))
		 (x54 (u16 (- x54 (+ (& x76 (~ x32)) (& x10 x32)
				     (vector-ref xkey (+ (* 4 i) 2))))))
		 (x32 (bitwise-ior (<< x32 14) (>> x32 2)))
		 (x32 (u16 (- x32 (+ (& x54 (~ x10)) (& x76 x10)
				     (vector-ref xkey (+ (* 4 i) 1))))))
		 (x10 (bitwise-ior (<< x10 15) (>> x10 1)))
		 (x10 (u16 (- x10 (+ (& x32 (~ x76)) (& x54 x76)
				     (vector-ref xkey (+ (* 4 i) 0)))))))
	    (loop x10 x32 x54 x76 (- i 1))))))
  8)

(define (rc2-done key) #t)

(define rc2-descriptor
  (symmetric-scheme-descriptor-builder
   (name "RC2")
   (key-length* '(5 . 128)) ;; min 5 for RC2 40bits
   (block-size 8)
   (default-round 16)
   (setupper rc2-setup)
   (encryptor rc2-encrypt)
   (decryptor rc2-decrypt)
   (finalizer rc2-done)))

(define permute
  #vu8(217 120 249 196  25 221 181 237  40 233 253 121  74 160 216 157 
       198 126  55 131  43 118  83 142  98  76 100 136  68 139 251 162 
        23 154  89 245 135 179  79  19  97  69 109 141   9 129 125  50 
       189 143  64 235 134 183 123  11 240 149  33  34  92 107  78 130 
        84 214 101 147 206  96 178  28 115  86 192  20 167 140 241 220 
        18 117 202  31  59 190 228 209  66  61 212  48 163  60 182  38 
       111 191  14 218  70 105   7  87  39 242  29 155 188 148  67   3 
       248  17 199 246 144 239  62 231   6 195 213  47 200 102  30 215 
         8 232 234 222 128  82 238 247 132 170 114 172  53  77 106  42 
       150  26 210 113  90  21  73 116  75 159 208  94   4  24 164 236 
       194 224  65 110  15  81 203 204  36 145 175  80 161 244 112  57 
       153 124  58 133  35 184 180 122 252   2  54  91  37  85 151  49 
        45  93 250 152 227 138 146 174   5 223  41  16 103 108 186 201 
       211   0 230 207 225 158 168  44  99  22   1  63  88 226 137 169 
        13  56  52  27 171  51 255 176 187  72  12  95 185 177 205  46 
       197 243 219  71 229 165 156 119  10 166  32 104 254 127 193 173))
)
