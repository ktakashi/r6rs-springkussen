;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/cipher/symmetric/scheme/aes.sls - AES operation
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
;; The implementation is from aeolus, which is written by me :)
(library (springkussen cipher symmetric scheme aes)
    (export aes-descriptor
	    aes-128-descriptor
	    aes-192-descriptor
	    aes-256-descriptor
	    )
    (import (rnrs)
	    (springkussen conditions)
	    (springkussen cipher symmetric scheme descriptor)
	    (springkussen misc bitwise))

(define-record-type aes-key
  (fields ek dk nr)
  (protocol (lambda (p)
	      (lambda (nr)
		(p (make-vector 60) (make-vector 60) nr)))))

(define (setup-mix temp)
  (bitwise-xor (vector-ref Te4_3 (byte temp 2))
	       (vector-ref Te4_2 (byte temp 1))
	       (vector-ref Te4_1 (byte temp 0))
	       (vector-ref Te4_0 (byte temp 3))))

(define (aes-setup key round)
  (define keylen (bytevector-length key))
  (define (create-aes-key key round)
    (let ((nr (+ 10 (* (- (div keylen 8) 2) 2))))
      (unless (or (zero? round) (= round nr))
	(springkussen-assertion-violation 'setup "invalid round" round nr))
      (make-aes-key nr)))
  (define vset! vector-set!)
  (define vref vector-ref)
  (define bxor bitwise-xor)
  (define (setup-ek skey)
    (let ((rk (aes-key-ek skey)))
      (vset! rk 0 (load32h key 0))
      (vset! rk 1 (load32h key 4))
      (vset! rk 2 (load32h key 8))
      (vset! rk 3 (load32h key 12))
      (case keylen
	((16)
	 (let loop ((i 0) (ri 0))
	   (let ((rk0 (vref rk ri))
		 (rk1 (vref rk (+ ri 1)))
		 (rk2 (vref rk (+ ri 2)))
		 (rk3 (vref rk (+ ri 3))))
	     (vset! rk (+ ri 4) (bxor rk0 (setup-mix rk3) (vref rcon i)))
	     (vset! rk (+ ri 5) (bxor rk1 (vref rk (+ ri 4))))
	     (vset! rk (+ ri 6) (bxor rk2 (vref rk (+ ri 5))))
	     (vset! rk (+ ri 7) (bxor rk3 (vref rk (+ ri 6))))
	     (unless (= (+ i 1) 10)
	       (loop (+ i 1) (+ ri 4))))))
	((24) 
	 (vset! rk 4 (load32h key 16))
	 (vset! rk 5 (load32h key 20))
	 (let loop ((i 0) (ri 0))
	   (let ((rk0 (vref rk ri))
		 (rk1 (vref rk (+ ri 1)))
		 (rk2 (vref rk (+ ri 2)))
		 (rk3 (vref rk (+ ri 3)))
		 (rk5 (vref rk (+ ri 5))))
	     (vset! rk (+ ri 6) (bxor rk0 (setup-mix rk5) (vref rcon i)))
	     (vset! rk (+ ri 7) (bxor rk1 (vref rk (+ ri 6))))
	     (vset! rk (+ ri 8) (bxor rk2 (vref rk (+ ri 7))))
	     (vset! rk (+ ri 9) (bxor rk3 (vref rk (+ ri 8))))
	     (unless (= (+ i 1) 8)
	       (let ((rk4 (vref rk (+ ri 4))))
		 (vset! rk (+ ri 10) (bxor rk4 (vref rk (+ ri 9))))
		 (vset! rk (+ ri 11) (bxor rk5 (vref rk (+ ri 10))))
		 (loop (+ i 1) (+ ri 6)))))))
	((32) 
	 (vset! rk 4 (load32h key 16))
	 (vset! rk 5 (load32h key 20))
	 (vset! rk 6 (load32h key 24))
	 (vset! rk 7 (load32h key 28))
	 (let loop ((i 0) (ri 0))
	   (let ((rk0 (vref rk ri))
		 (rk1 (vref rk (+ ri 1)))
		 (rk2 (vref rk (+ ri 2)))
		 (rk3 (vref rk (+ ri 3)))
		 (rk7 (vref rk (+ ri 7))))
	     (vset! rk (+ ri 8)  (bxor rk0 (setup-mix rk7) (vref rcon i)))
	     (vset! rk (+ ri 9)  (bxor rk1 (vref rk (+ ri 8))))
	     (vset! rk (+ ri 10) (bxor rk2 (vref rk (+ ri 9))))
	     (vset! rk (+ ri 11) (bxor rk3 (vref rk (+ ri 10))))
	     (unless (= (+ i 1) 7)
	       (let ((rk4 (vref rk (+ ri 4)))
		     (rk5 (vref rk (+ ri 5)))
		     (rk6 (vref rk (+ ri 6)))
		     (rk11 (vref rk (+ ri 11))))
		 (vset! rk (+ ri 12) (bxor rk4 (setup-mix (rorc rk11 8))))
		 (vset! rk (+ ri 13) (bxor rk5 (vref rk (+ ri 12))))
		 (vset! rk (+ ri 14) (bxor rk6 (vref rk (+ ri 13))))
		 (vset! rk (+ ri 15) (bxor rk7 (vref rk (+ ri 14))))
		 (loop (+ i 1) (+ ri 8))))))))))

  (define (setup-dk skey)
    (define (copy4 rk rrk rki rrki)
      (do ((i 0 (+ i 1)))
	  ((= i 4))
	(vset! rk (+ i rki) (vref rrk (+ i rrki)))))
    (let ((rk (aes-key-dk skey))
	  (rrk (aes-key-ek skey))
	  (rrki (- (+ 28 keylen) 4)))
      (define (set-it rrk rki rrki index)
	(let ((temp (vref rrk (+ rrki index))))
	  (vset! rk (+ rki index)
		 (bxor (vref Tks0 (byte temp 3))
		       (vref Tks1 (byte temp 2))
		       (vref Tks2 (byte temp 1))
		       (vref Tks3 (byte temp 0))))))
      (copy4 rk rrk 0 rrki)
      (do ((i 1 (+ i 1)) 
	   (rrki (- rrki 4) (- rrki 4)) 
	   (rki 4 (+ rki 4))
	   (nr (aes-key-nr skey)))
	  ((= i nr)
	   ;; copy last
	   (copy4 rk rrk rki rrki)
	   skey)
	(set-it rrk rki rrki 0)
	(set-it rrk rki rrki 1)
	(set-it rrk rki rrki 2)
	(set-it rrk rki rrki 3))))
  
  (let ((skey (create-aes-key key round)))
    (setup-ek skey)
    (setup-dk skey)))

(define (aes-encrypt pt ps ct cs key)
  (define nr (aes-key-nr key))
  (define rk (aes-key-ek key))
  (define (round nr rk)
    (define (compute-t rk rki s0 s1 s2 s3)
      (bitwise-xor (Te0 (byte s0 3))
		   (Te1 (byte s1 2))
		   (Te2 (byte s2 1))
		   (Te3 (byte s3 0))
		   (vector-ref rk rki)))
    (let loop ((r (div nr 2))
	       (rki 0)
	       (s0 (bitwise-xor (load32h pt ps)        (vector-ref rk 0)))
	       (s1 (bitwise-xor (load32h pt (+ ps 4))  (vector-ref rk 1)))
	       (s2 (bitwise-xor (load32h pt (+ ps 8))  (vector-ref rk 2)))
	       (s3 (bitwise-xor (load32h pt (+ ps 12)) (vector-ref rk 3))))
      (let ((t0 (compute-t rk (+ rki 4) s0 s1 s2 s3))
	    (t1 (compute-t rk (+ rki 5) s1 s2 s3 s0))
	    (t2 (compute-t rk (+ rki 6) s2 s3 s0 s1))
	    (t3 (compute-t rk (+ rki 7) s3 s0 s1 s2))
	    (rki (+ rki 8))
	    (r (- r 1)))
	(if (zero? r)
	    (values rki t0 t1 t2 t3)
	    (loop r rki 
		  (compute-t rk rki       t0 t1 t2 t3)
		  (compute-t rk (+ rki 1) t1 t2 t3 t0)
		  (compute-t rk (+ rki 2) t2 t3 t0 t1)
		  (compute-t rk (+ rki 3) t3 t0 t1 t2))))))
  ;; should we check size of pt?
  (let-values (((rki t0 t1 t2 t3) (round nr rk)))
    (define (compute-s rk rki t0 t1 t2 t3)
      (bitwise-xor (vector-ref Te4_3 (byte t0 3))
		   (vector-ref Te4_2 (byte t1 2))
		   (vector-ref Te4_1 (byte t2 1))
		   (vector-ref Te4_0 (byte t3 0))
		   (vector-ref rk rki)))
    (store32h ct cs        (compute-s rk rki       t0 t1 t2 t3))
    (store32h ct (+ cs 4)  (compute-s rk (+ rki 1) t1 t2 t3 t0))
    (store32h ct (+ cs 8)  (compute-s rk (+ rki 2) t2 t3 t0 t1))
    (store32h ct (+ cs 12) (compute-s rk (+ rki 3) t3 t0 t1 t2))
    16))

(define (aes-decrypt ct cs pt ps key)
  (define nr (aes-key-nr key))
  (define rk (aes-key-dk key))
  (define (round nr rk)
    (let loop ((r (div nr 2))
	       (rki 0)
	       (s0 (bitwise-xor (load32h ct (+ cs 0))  (vector-ref rk 0)))
	       (s1 (bitwise-xor (load32h ct (+ cs 4))  (vector-ref rk 1)))
	       (s2 (bitwise-xor (load32h ct (+ cs 8))  (vector-ref rk 2)))
	       (s3 (bitwise-xor (load32h ct (+ cs 12)) (vector-ref rk 3))))
      (define (compute-t rk rki s0 s1 s2 s3)
	(bitwise-xor (Td0 (byte s0 3))
		     (Td1 (byte s1 2))
		     (Td2 (byte s2 1))
		     (Td3 (byte s3 0))
		     (vector-ref rk rki)))
      
      (let ((t0 (compute-t rk (+ rki 4) s0 s3 s2 s1))
	    (t1 (compute-t rk (+ rki 5) s1 s0 s3 s2))
	    (t2 (compute-t rk (+ rki 6) s2 s1 s0 s3))
	    (t3 (compute-t rk (+ rki 7) s3 s2 s1 s0))
	    (rki (+ rki 8))
	    (r (- r 1)))
	(if (zero? r)
	    (values rki t0 t1 t2 t3)
	    (loop r rki 
		  (compute-t rk (+ rki 0) t0 t3 t2 t1)
		  (compute-t rk (+ rki 1) t1 t0 t3 t2)
		  (compute-t rk (+ rki 2) t2 t1 t0 t3)
		  (compute-t rk (+ rki 3) t3 t2 t1 t0))))))
  ;; should we check size of pt?
  (let-values (((rki t0 t1 t2 t3) (round nr rk)))
    (define (compute-s rk rki t0 t1 t2 t3)
      (bitwise-xor (bitwise-and (vector-ref Td4 (byte t0 3)) #xff000000)
		   (bitwise-and (vector-ref Td4 (byte t1 2)) #x00ff0000)
		   (bitwise-and (vector-ref Td4 (byte t2 1)) #x0000ff00)
		   (bitwise-and (vector-ref Td4 (byte t3 0)) #x000000ff)
		   (vector-ref rk rki)))
    (store32h pt (+ ps 0) (compute-s rk (+ rki 0) t0 t3 t2 t1))
    (store32h pt (+ ps 4) (compute-s rk (+ rki 1) t1 t0 t3 t2))
    (store32h pt (+ ps 8) (compute-s rk (+ rki 2) t2 t1 t0 t3))
    (store32h pt (+ ps 12) (compute-s rk (+ rki 3) t3 t2 t1 t0))
    16))

(define (aes-done key) #t)

(define aes-descriptor
  (symmetric-scheme-descriptor-builder
   (name "AES")
   (key-length* '(16 24 32))
   (block-size 16)
   (default-round 10)
   (setupper aes-setup)
   (encryptor aes-encrypt)
   (decryptor aes-decrypt)
   (finalizer aes-done)))

(define aes-128-descriptor
  (symmetric-scheme-descriptor-builder
   (name "AES-128")
   (key-length* '(16))
   (block-size 16)
   (default-round 10)
   (setupper aes-setup)
   (encryptor aes-encrypt)
   (decryptor aes-decrypt)
   (finalizer aes-done)))

(define aes-192-descriptor
  (symmetric-scheme-descriptor-builder
   (name "AES-192")
   (key-length* '(24))
   (block-size 16)
   (default-round 10)
   (setupper aes-setup)
   (encryptor aes-encrypt)
   (decryptor aes-decrypt)
   (finalizer aes-done)))

(define aes-256-descriptor
  (symmetric-scheme-descriptor-builder
   (name "AES-256")
   (key-length* '(32))
   (block-size 16)
   (default-round 10)
   (setupper aes-setup)
   (encryptor aes-encrypt)
   (decryptor aes-decrypt)
   (finalizer aes-done)))


;;;; AES tables
(define TE0 '#(
    #xc66363a5 #xf87c7c84 #xee777799 #xf67b7b8d
    #xfff2f20d #xd66b6bbd #xde6f6fb1 #x91c5c554
    #x60303050 #x02010103 #xce6767a9 #x562b2b7d
    #xe7fefe19 #xb5d7d762 #x4dababe6 #xec76769a
    #x8fcaca45 #x1f82829d #x89c9c940 #xfa7d7d87
    #xeffafa15 #xb25959eb #x8e4747c9 #xfbf0f00b
    #x41adadec #xb3d4d467 #x5fa2a2fd #x45afafea
    #x239c9cbf #x53a4a4f7 #xe4727296 #x9bc0c05b
    #x75b7b7c2 #xe1fdfd1c #x3d9393ae #x4c26266a
    #x6c36365a #x7e3f3f41 #xf5f7f702 #x83cccc4f
    #x6834345c #x51a5a5f4 #xd1e5e534 #xf9f1f108
    #xe2717193 #xabd8d873 #x62313153 #x2a15153f
    #x0804040c #x95c7c752 #x46232365 #x9dc3c35e
    #x30181828 #x379696a1 #x0a05050f #x2f9a9ab5
    #x0e070709 #x24121236 #x1b80809b #xdfe2e23d
    #xcdebeb26 #x4e272769 #x7fb2b2cd #xea75759f
    #x1209091b #x1d83839e #x582c2c74 #x341a1a2e
    #x361b1b2d #xdc6e6eb2 #xb45a5aee #x5ba0a0fb
    #xa45252f6 #x763b3b4d #xb7d6d661 #x7db3b3ce
    #x5229297b #xdde3e33e #x5e2f2f71 #x13848497
    #xa65353f5 #xb9d1d168 #x00000000 #xc1eded2c
    #x40202060 #xe3fcfc1f #x79b1b1c8 #xb65b5bed
    #xd46a6abe #x8dcbcb46 #x67bebed9 #x7239394b
    #x944a4ade #x984c4cd4 #xb05858e8 #x85cfcf4a
    #xbbd0d06b #xc5efef2a #x4faaaae5 #xedfbfb16
    #x864343c5 #x9a4d4dd7 #x66333355 #x11858594
    #x8a4545cf #xe9f9f910 #x04020206 #xfe7f7f81
    #xa05050f0 #x783c3c44 #x259f9fba #x4ba8a8e3
    #xa25151f3 #x5da3a3fe #x804040c0 #x058f8f8a
    #x3f9292ad #x219d9dbc #x70383848 #xf1f5f504
    #x63bcbcdf #x77b6b6c1 #xafdada75 #x42212163
    #x20101030 #xe5ffff1a #xfdf3f30e #xbfd2d26d
    #x81cdcd4c #x180c0c14 #x26131335 #xc3ecec2f
    #xbe5f5fe1 #x359797a2 #x884444cc #x2e171739
    #x93c4c457 #x55a7a7f2 #xfc7e7e82 #x7a3d3d47
    #xc86464ac #xba5d5de7 #x3219192b #xe6737395
    #xc06060a0 #x19818198 #x9e4f4fd1 #xa3dcdc7f
    #x44222266 #x542a2a7e #x3b9090ab #x0b888883
    #x8c4646ca #xc7eeee29 #x6bb8b8d3 #x2814143c
    #xa7dede79 #xbc5e5ee2 #x160b0b1d #xaddbdb76
    #xdbe0e03b #x64323256 #x743a3a4e #x140a0a1e
    #x924949db #x0c06060a #x4824246c #xb85c5ce4
    #x9fc2c25d #xbdd3d36e #x43acacef #xc46262a6
    #x399191a8 #x319595a4 #xd3e4e437 #xf279798b
    #xd5e7e732 #x8bc8c843 #x6e373759 #xda6d6db7
    #x018d8d8c #xb1d5d564 #x9c4e4ed2 #x49a9a9e0
    #xd86c6cb4 #xac5656fa #xf3f4f407 #xcfeaea25
    #xca6565af #xf47a7a8e #x47aeaee9 #x10080818
    #x6fbabad5 #xf0787888 #x4a25256f #x5c2e2e72
    #x381c1c24 #x57a6a6f1 #x73b4b4c7 #x97c6c651
    #xcbe8e823 #xa1dddd7c #xe874749c #x3e1f1f21
    #x964b4bdd #x61bdbddc #x0d8b8b86 #x0f8a8a85
    #xe0707090 #x7c3e3e42 #x71b5b5c4 #xcc6666aa
    #x904848d8 #x06030305 #xf7f6f601 #x1c0e0e12
    #xc26161a3 #x6a35355f #xae5757f9 #x69b9b9d0
    #x17868691 #x99c1c158 #x3a1d1d27 #x279e9eb9
    #xd9e1e138 #xebf8f813 #x2b9898b3 #x22111133
    #xd26969bb #xa9d9d970 #x078e8e89 #x339494a7
    #x2d9b9bb6 #x3c1e1e22 #x15878792 #xc9e9e920
    #x87cece49 #xaa5555ff #x50282878 #xa5dfdf7a
    #x038c8c8f #x59a1a1f8 #x09898980 #x1a0d0d17
    #x65bfbfda #xd7e6e631 #x844242c6 #xd06868b8
    #x824141c3 #x299999b0 #x5a2d2d77 #x1e0f0f11
    #x7bb0b0cb #xa85454fc #x6dbbbbd6 #x2c16163a
))

(define TE1 '#(
    #xa5c66363 #x84f87c7c #x99ee7777 #x8df67b7b
    #x0dfff2f2 #xbdd66b6b #xb1de6f6f #x5491c5c5
    #x50603030 #x03020101 #xa9ce6767 #x7d562b2b
    #x19e7fefe #x62b5d7d7 #xe64dabab #x9aec7676
    #x458fcaca #x9d1f8282 #x4089c9c9 #x87fa7d7d
    #x15effafa #xebb25959 #xc98e4747 #x0bfbf0f0
    #xec41adad #x67b3d4d4 #xfd5fa2a2 #xea45afaf
    #xbf239c9c #xf753a4a4 #x96e47272 #x5b9bc0c0
    #xc275b7b7 #x1ce1fdfd #xae3d9393 #x6a4c2626
    #x5a6c3636 #x417e3f3f #x02f5f7f7 #x4f83cccc
    #x5c683434 #xf451a5a5 #x34d1e5e5 #x08f9f1f1
    #x93e27171 #x73abd8d8 #x53623131 #x3f2a1515
    #x0c080404 #x5295c7c7 #x65462323 #x5e9dc3c3
    #x28301818 #xa1379696 #x0f0a0505 #xb52f9a9a
    #x090e0707 #x36241212 #x9b1b8080 #x3ddfe2e2
    #x26cdebeb #x694e2727 #xcd7fb2b2 #x9fea7575
    #x1b120909 #x9e1d8383 #x74582c2c #x2e341a1a
    #x2d361b1b #xb2dc6e6e #xeeb45a5a #xfb5ba0a0
    #xf6a45252 #x4d763b3b #x61b7d6d6 #xce7db3b3
    #x7b522929 #x3edde3e3 #x715e2f2f #x97138484
    #xf5a65353 #x68b9d1d1 #x00000000 #x2cc1eded
    #x60402020 #x1fe3fcfc #xc879b1b1 #xedb65b5b
    #xbed46a6a #x468dcbcb #xd967bebe #x4b723939
    #xde944a4a #xd4984c4c #xe8b05858 #x4a85cfcf
    #x6bbbd0d0 #x2ac5efef #xe54faaaa #x16edfbfb
    #xc5864343 #xd79a4d4d #x55663333 #x94118585
    #xcf8a4545 #x10e9f9f9 #x06040202 #x81fe7f7f
    #xf0a05050 #x44783c3c #xba259f9f #xe34ba8a8
    #xf3a25151 #xfe5da3a3 #xc0804040 #x8a058f8f
    #xad3f9292 #xbc219d9d #x48703838 #x04f1f5f5
    #xdf63bcbc #xc177b6b6 #x75afdada #x63422121
    #x30201010 #x1ae5ffff #x0efdf3f3 #x6dbfd2d2
    #x4c81cdcd #x14180c0c #x35261313 #x2fc3ecec
    #xe1be5f5f #xa2359797 #xcc884444 #x392e1717
    #x5793c4c4 #xf255a7a7 #x82fc7e7e #x477a3d3d
    #xacc86464 #xe7ba5d5d #x2b321919 #x95e67373
    #xa0c06060 #x98198181 #xd19e4f4f #x7fa3dcdc
    #x66442222 #x7e542a2a #xab3b9090 #x830b8888
    #xca8c4646 #x29c7eeee #xd36bb8b8 #x3c281414
    #x79a7dede #xe2bc5e5e #x1d160b0b #x76addbdb
    #x3bdbe0e0 #x56643232 #x4e743a3a #x1e140a0a
    #xdb924949 #x0a0c0606 #x6c482424 #xe4b85c5c
    #x5d9fc2c2 #x6ebdd3d3 #xef43acac #xa6c46262
    #xa8399191 #xa4319595 #x37d3e4e4 #x8bf27979
    #x32d5e7e7 #x438bc8c8 #x596e3737 #xb7da6d6d
    #x8c018d8d #x64b1d5d5 #xd29c4e4e #xe049a9a9
    #xb4d86c6c #xfaac5656 #x07f3f4f4 #x25cfeaea
    #xafca6565 #x8ef47a7a #xe947aeae #x18100808
    #xd56fbaba #x88f07878 #x6f4a2525 #x725c2e2e
    #x24381c1c #xf157a6a6 #xc773b4b4 #x5197c6c6
    #x23cbe8e8 #x7ca1dddd #x9ce87474 #x213e1f1f
    #xdd964b4b #xdc61bdbd #x860d8b8b #x850f8a8a
    #x90e07070 #x427c3e3e #xc471b5b5 #xaacc6666
    #xd8904848 #x05060303 #x01f7f6f6 #x121c0e0e
    #xa3c26161 #x5f6a3535 #xf9ae5757 #xd069b9b9
    #x91178686 #x5899c1c1 #x273a1d1d #xb9279e9e
    #x38d9e1e1 #x13ebf8f8 #xb32b9898 #x33221111
    #xbbd26969 #x70a9d9d9 #x89078e8e #xa7339494
    #xb62d9b9b #x223c1e1e #x92158787 #x20c9e9e9
    #x4987cece #xffaa5555 #x78502828 #x7aa5dfdf
    #x8f038c8c #xf859a1a1 #x80098989 #x171a0d0d
    #xda65bfbf #x31d7e6e6 #xc6844242 #xb8d06868
    #xc3824141 #xb0299999 #x775a2d2d #x111e0f0f
    #xcb7bb0b0 #xfca85454 #xd66dbbbb #x3a2c1616
))
(define TE2 '#(
    #x63a5c663 #x7c84f87c #x7799ee77 #x7b8df67b
    #xf20dfff2 #x6bbdd66b #x6fb1de6f #xc55491c5
    #x30506030 #x01030201 #x67a9ce67 #x2b7d562b
    #xfe19e7fe #xd762b5d7 #xabe64dab #x769aec76
    #xca458fca #x829d1f82 #xc94089c9 #x7d87fa7d
    #xfa15effa #x59ebb259 #x47c98e47 #xf00bfbf0
    #xadec41ad #xd467b3d4 #xa2fd5fa2 #xafea45af
    #x9cbf239c #xa4f753a4 #x7296e472 #xc05b9bc0
    #xb7c275b7 #xfd1ce1fd #x93ae3d93 #x266a4c26
    #x365a6c36 #x3f417e3f #xf702f5f7 #xcc4f83cc
    #x345c6834 #xa5f451a5 #xe534d1e5 #xf108f9f1
    #x7193e271 #xd873abd8 #x31536231 #x153f2a15
    #x040c0804 #xc75295c7 #x23654623 #xc35e9dc3
    #x18283018 #x96a13796 #x050f0a05 #x9ab52f9a
    #x07090e07 #x12362412 #x809b1b80 #xe23ddfe2
    #xeb26cdeb #x27694e27 #xb2cd7fb2 #x759fea75
    #x091b1209 #x839e1d83 #x2c74582c #x1a2e341a
    #x1b2d361b #x6eb2dc6e #x5aeeb45a #xa0fb5ba0
    #x52f6a452 #x3b4d763b #xd661b7d6 #xb3ce7db3
    #x297b5229 #xe33edde3 #x2f715e2f #x84971384
    #x53f5a653 #xd168b9d1 #x00000000 #xed2cc1ed
    #x20604020 #xfc1fe3fc #xb1c879b1 #x5bedb65b
    #x6abed46a #xcb468dcb #xbed967be #x394b7239
    #x4ade944a #x4cd4984c #x58e8b058 #xcf4a85cf
    #xd06bbbd0 #xef2ac5ef #xaae54faa #xfb16edfb
    #x43c58643 #x4dd79a4d #x33556633 #x85941185
    #x45cf8a45 #xf910e9f9 #x02060402 #x7f81fe7f
    #x50f0a050 #x3c44783c #x9fba259f #xa8e34ba8
    #x51f3a251 #xa3fe5da3 #x40c08040 #x8f8a058f
    #x92ad3f92 #x9dbc219d #x38487038 #xf504f1f5
    #xbcdf63bc #xb6c177b6 #xda75afda #x21634221
    #x10302010 #xff1ae5ff #xf30efdf3 #xd26dbfd2
    #xcd4c81cd #x0c14180c #x13352613 #xec2fc3ec
    #x5fe1be5f #x97a23597 #x44cc8844 #x17392e17
    #xc45793c4 #xa7f255a7 #x7e82fc7e #x3d477a3d
    #x64acc864 #x5de7ba5d #x192b3219 #x7395e673
    #x60a0c060 #x81981981 #x4fd19e4f #xdc7fa3dc
    #x22664422 #x2a7e542a #x90ab3b90 #x88830b88
    #x46ca8c46 #xee29c7ee #xb8d36bb8 #x143c2814
    #xde79a7de #x5ee2bc5e #x0b1d160b #xdb76addb
    #xe03bdbe0 #x32566432 #x3a4e743a #x0a1e140a
    #x49db9249 #x060a0c06 #x246c4824 #x5ce4b85c
    #xc25d9fc2 #xd36ebdd3 #xacef43ac #x62a6c462
    #x91a83991 #x95a43195 #xe437d3e4 #x798bf279
    #xe732d5e7 #xc8438bc8 #x37596e37 #x6db7da6d
    #x8d8c018d #xd564b1d5 #x4ed29c4e #xa9e049a9
    #x6cb4d86c #x56faac56 #xf407f3f4 #xea25cfea
    #x65afca65 #x7a8ef47a #xaee947ae #x08181008
    #xbad56fba #x7888f078 #x256f4a25 #x2e725c2e
    #x1c24381c #xa6f157a6 #xb4c773b4 #xc65197c6
    #xe823cbe8 #xdd7ca1dd #x749ce874 #x1f213e1f
    #x4bdd964b #xbddc61bd #x8b860d8b #x8a850f8a
    #x7090e070 #x3e427c3e #xb5c471b5 #x66aacc66
    #x48d89048 #x03050603 #xf601f7f6 #x0e121c0e
    #x61a3c261 #x355f6a35 #x57f9ae57 #xb9d069b9
    #x86911786 #xc15899c1 #x1d273a1d #x9eb9279e
    #xe138d9e1 #xf813ebf8 #x98b32b98 #x11332211
    #x69bbd269 #xd970a9d9 #x8e89078e #x94a73394
    #x9bb62d9b #x1e223c1e #x87921587 #xe920c9e9
    #xce4987ce #x55ffaa55 #x28785028 #xdf7aa5df
    #x8c8f038c #xa1f859a1 #x89800989 #x0d171a0d
    #xbfda65bf #xe631d7e6 #x42c68442 #x68b8d068
    #x41c38241 #x99b02999 #x2d775a2d #x0f111e0f
    #xb0cb7bb0 #x54fca854 #xbbd66dbb #x163a2c16
))
(define TE3 '#(

    #x6363a5c6 #x7c7c84f8 #x777799ee #x7b7b8df6
    #xf2f20dff #x6b6bbdd6 #x6f6fb1de #xc5c55491
    #x30305060 #x01010302 #x6767a9ce #x2b2b7d56
    #xfefe19e7 #xd7d762b5 #xababe64d #x76769aec
    #xcaca458f #x82829d1f #xc9c94089 #x7d7d87fa
    #xfafa15ef #x5959ebb2 #x4747c98e #xf0f00bfb
    #xadadec41 #xd4d467b3 #xa2a2fd5f #xafafea45
    #x9c9cbf23 #xa4a4f753 #x727296e4 #xc0c05b9b
    #xb7b7c275 #xfdfd1ce1 #x9393ae3d #x26266a4c
    #x36365a6c #x3f3f417e #xf7f702f5 #xcccc4f83
    #x34345c68 #xa5a5f451 #xe5e534d1 #xf1f108f9
    #x717193e2 #xd8d873ab #x31315362 #x15153f2a
    #x04040c08 #xc7c75295 #x23236546 #xc3c35e9d
    #x18182830 #x9696a137 #x05050f0a #x9a9ab52f
    #x0707090e #x12123624 #x80809b1b #xe2e23ddf
    #xebeb26cd #x2727694e #xb2b2cd7f #x75759fea
    #x09091b12 #x83839e1d #x2c2c7458 #x1a1a2e34
    #x1b1b2d36 #x6e6eb2dc #x5a5aeeb4 #xa0a0fb5b
    #x5252f6a4 #x3b3b4d76 #xd6d661b7 #xb3b3ce7d
    #x29297b52 #xe3e33edd #x2f2f715e #x84849713
    #x5353f5a6 #xd1d168b9 #x00000000 #xeded2cc1
    #x20206040 #xfcfc1fe3 #xb1b1c879 #x5b5bedb6
    #x6a6abed4 #xcbcb468d #xbebed967 #x39394b72
    #x4a4ade94 #x4c4cd498 #x5858e8b0 #xcfcf4a85
    #xd0d06bbb #xefef2ac5 #xaaaae54f #xfbfb16ed
    #x4343c586 #x4d4dd79a #x33335566 #x85859411
    #x4545cf8a #xf9f910e9 #x02020604 #x7f7f81fe
    #x5050f0a0 #x3c3c4478 #x9f9fba25 #xa8a8e34b
    #x5151f3a2 #xa3a3fe5d #x4040c080 #x8f8f8a05
    #x9292ad3f #x9d9dbc21 #x38384870 #xf5f504f1
    #xbcbcdf63 #xb6b6c177 #xdada75af #x21216342
    #x10103020 #xffff1ae5 #xf3f30efd #xd2d26dbf
    #xcdcd4c81 #x0c0c1418 #x13133526 #xecec2fc3
    #x5f5fe1be #x9797a235 #x4444cc88 #x1717392e
    #xc4c45793 #xa7a7f255 #x7e7e82fc #x3d3d477a
    #x6464acc8 #x5d5de7ba #x19192b32 #x737395e6
    #x6060a0c0 #x81819819 #x4f4fd19e #xdcdc7fa3
    #x22226644 #x2a2a7e54 #x9090ab3b #x8888830b
    #x4646ca8c #xeeee29c7 #xb8b8d36b #x14143c28
    #xdede79a7 #x5e5ee2bc #x0b0b1d16 #xdbdb76ad
    #xe0e03bdb #x32325664 #x3a3a4e74 #x0a0a1e14
    #x4949db92 #x06060a0c #x24246c48 #x5c5ce4b8
    #xc2c25d9f #xd3d36ebd #xacacef43 #x6262a6c4
    #x9191a839 #x9595a431 #xe4e437d3 #x79798bf2
    #xe7e732d5 #xc8c8438b #x3737596e #x6d6db7da
    #x8d8d8c01 #xd5d564b1 #x4e4ed29c #xa9a9e049
    #x6c6cb4d8 #x5656faac #xf4f407f3 #xeaea25cf
    #x6565afca #x7a7a8ef4 #xaeaee947 #x08081810
    #xbabad56f #x787888f0 #x25256f4a #x2e2e725c
    #x1c1c2438 #xa6a6f157 #xb4b4c773 #xc6c65197
    #xe8e823cb #xdddd7ca1 #x74749ce8 #x1f1f213e
    #x4b4bdd96 #xbdbddc61 #x8b8b860d #x8a8a850f
    #x707090e0 #x3e3e427c #xb5b5c471 #x6666aacc
    #x4848d890 #x03030506 #xf6f601f7 #x0e0e121c
    #x6161a3c2 #x35355f6a #x5757f9ae #xb9b9d069
    #x86869117 #xc1c15899 #x1d1d273a #x9e9eb927
    #xe1e138d9 #xf8f813eb #x9898b32b #x11113322
    #x6969bbd2 #xd9d970a9 #x8e8e8907 #x9494a733
    #x9b9bb62d #x1e1e223c #x87879215 #xe9e920c9
    #xcece4987 #x5555ffaa #x28287850 #xdfdf7aa5
    #x8c8c8f03 #xa1a1f859 #x89898009 #x0d0d171a
    #xbfbfda65 #xe6e631d7 #x4242c684 #x6868b8d0
    #x4141c382 #x9999b029 #x2d2d775a #x0f0f111e
    #xb0b0cb7b #x5454fca8 #xbbbbd66d #x16163a2c
))

(define Te4_0 '#(
#x00000063 #x0000007c #x00000077 #x0000007b #x000000f2 #x0000006b #x0000006f #x000000c5
#x00000030 #x00000001 #x00000067 #x0000002b #x000000fe #x000000d7 #x000000ab #x00000076
#x000000ca #x00000082 #x000000c9 #x0000007d #x000000fa #x00000059 #x00000047 #x000000f0
#x000000ad #x000000d4 #x000000a2 #x000000af #x0000009c #x000000a4 #x00000072 #x000000c0
#x000000b7 #x000000fd #x00000093 #x00000026 #x00000036 #x0000003f #x000000f7 #x000000cc
#x00000034 #x000000a5 #x000000e5 #x000000f1 #x00000071 #x000000d8 #x00000031 #x00000015
#x00000004 #x000000c7 #x00000023 #x000000c3 #x00000018 #x00000096 #x00000005 #x0000009a
#x00000007 #x00000012 #x00000080 #x000000e2 #x000000eb #x00000027 #x000000b2 #x00000075
#x00000009 #x00000083 #x0000002c #x0000001a #x0000001b #x0000006e #x0000005a #x000000a0
#x00000052 #x0000003b #x000000d6 #x000000b3 #x00000029 #x000000e3 #x0000002f #x00000084
#x00000053 #x000000d1 #x00000000 #x000000ed #x00000020 #x000000fc #x000000b1 #x0000005b
#x0000006a #x000000cb #x000000be #x00000039 #x0000004a #x0000004c #x00000058 #x000000cf
#x000000d0 #x000000ef #x000000aa #x000000fb #x00000043 #x0000004d #x00000033 #x00000085
#x00000045 #x000000f9 #x00000002 #x0000007f #x00000050 #x0000003c #x0000009f #x000000a8
#x00000051 #x000000a3 #x00000040 #x0000008f #x00000092 #x0000009d #x00000038 #x000000f5
#x000000bc #x000000b6 #x000000da #x00000021 #x00000010 #x000000ff #x000000f3 #x000000d2
#x000000cd #x0000000c #x00000013 #x000000ec #x0000005f #x00000097 #x00000044 #x00000017
#x000000c4 #x000000a7 #x0000007e #x0000003d #x00000064 #x0000005d #x00000019 #x00000073
#x00000060 #x00000081 #x0000004f #x000000dc #x00000022 #x0000002a #x00000090 #x00000088
#x00000046 #x000000ee #x000000b8 #x00000014 #x000000de #x0000005e #x0000000b #x000000db
#x000000e0 #x00000032 #x0000003a #x0000000a #x00000049 #x00000006 #x00000024 #x0000005c
#x000000c2 #x000000d3 #x000000ac #x00000062 #x00000091 #x00000095 #x000000e4 #x00000079
#x000000e7 #x000000c8 #x00000037 #x0000006d #x0000008d #x000000d5 #x0000004e #x000000a9
#x0000006c #x00000056 #x000000f4 #x000000ea #x00000065 #x0000007a #x000000ae #x00000008
#x000000ba #x00000078 #x00000025 #x0000002e #x0000001c #x000000a6 #x000000b4 #x000000c6
#x000000e8 #x000000dd #x00000074 #x0000001f #x0000004b #x000000bd #x0000008b #x0000008a
#x00000070 #x0000003e #x000000b5 #x00000066 #x00000048 #x00000003 #x000000f6 #x0000000e
#x00000061 #x00000035 #x00000057 #x000000b9 #x00000086 #x000000c1 #x0000001d #x0000009e
#x000000e1 #x000000f8 #x00000098 #x00000011 #x00000069 #x000000d9 #x0000008e #x00000094
#x0000009b #x0000001e #x00000087 #x000000e9 #x000000ce #x00000055 #x00000028 #x000000df
#x0000008c #x000000a1 #x00000089 #x0000000d #x000000bf #x000000e6 #x00000042 #x00000068
#x00000041 #x00000099 #x0000002d #x0000000f #x000000b0 #x00000054 #x000000bb #x00000016
))

(define Te4_1 '#(
#x00006300 #x00007c00 #x00007700 #x00007b00 #x0000f200 #x00006b00 #x00006f00 #x0000c500
#x00003000 #x00000100 #x00006700 #x00002b00 #x0000fe00 #x0000d700 #x0000ab00 #x00007600
#x0000ca00 #x00008200 #x0000c900 #x00007d00 #x0000fa00 #x00005900 #x00004700 #x0000f000
#x0000ad00 #x0000d400 #x0000a200 #x0000af00 #x00009c00 #x0000a400 #x00007200 #x0000c000
#x0000b700 #x0000fd00 #x00009300 #x00002600 #x00003600 #x00003f00 #x0000f700 #x0000cc00
#x00003400 #x0000a500 #x0000e500 #x0000f100 #x00007100 #x0000d800 #x00003100 #x00001500
#x00000400 #x0000c700 #x00002300 #x0000c300 #x00001800 #x00009600 #x00000500 #x00009a00
#x00000700 #x00001200 #x00008000 #x0000e200 #x0000eb00 #x00002700 #x0000b200 #x00007500
#x00000900 #x00008300 #x00002c00 #x00001a00 #x00001b00 #x00006e00 #x00005a00 #x0000a000
#x00005200 #x00003b00 #x0000d600 #x0000b300 #x00002900 #x0000e300 #x00002f00 #x00008400
#x00005300 #x0000d100 #x00000000 #x0000ed00 #x00002000 #x0000fc00 #x0000b100 #x00005b00
#x00006a00 #x0000cb00 #x0000be00 #x00003900 #x00004a00 #x00004c00 #x00005800 #x0000cf00
#x0000d000 #x0000ef00 #x0000aa00 #x0000fb00 #x00004300 #x00004d00 #x00003300 #x00008500
#x00004500 #x0000f900 #x00000200 #x00007f00 #x00005000 #x00003c00 #x00009f00 #x0000a800
#x00005100 #x0000a300 #x00004000 #x00008f00 #x00009200 #x00009d00 #x00003800 #x0000f500
#x0000bc00 #x0000b600 #x0000da00 #x00002100 #x00001000 #x0000ff00 #x0000f300 #x0000d200
#x0000cd00 #x00000c00 #x00001300 #x0000ec00 #x00005f00 #x00009700 #x00004400 #x00001700
#x0000c400 #x0000a700 #x00007e00 #x00003d00 #x00006400 #x00005d00 #x00001900 #x00007300
#x00006000 #x00008100 #x00004f00 #x0000dc00 #x00002200 #x00002a00 #x00009000 #x00008800
#x00004600 #x0000ee00 #x0000b800 #x00001400 #x0000de00 #x00005e00 #x00000b00 #x0000db00
#x0000e000 #x00003200 #x00003a00 #x00000a00 #x00004900 #x00000600 #x00002400 #x00005c00
#x0000c200 #x0000d300 #x0000ac00 #x00006200 #x00009100 #x00009500 #x0000e400 #x00007900
#x0000e700 #x0000c800 #x00003700 #x00006d00 #x00008d00 #x0000d500 #x00004e00 #x0000a900
#x00006c00 #x00005600 #x0000f400 #x0000ea00 #x00006500 #x00007a00 #x0000ae00 #x00000800
#x0000ba00 #x00007800 #x00002500 #x00002e00 #x00001c00 #x0000a600 #x0000b400 #x0000c600
#x0000e800 #x0000dd00 #x00007400 #x00001f00 #x00004b00 #x0000bd00 #x00008b00 #x00008a00
#x00007000 #x00003e00 #x0000b500 #x00006600 #x00004800 #x00000300 #x0000f600 #x00000e00
#x00006100 #x00003500 #x00005700 #x0000b900 #x00008600 #x0000c100 #x00001d00 #x00009e00
#x0000e100 #x0000f800 #x00009800 #x00001100 #x00006900 #x0000d900 #x00008e00 #x00009400
#x00009b00 #x00001e00 #x00008700 #x0000e900 #x0000ce00 #x00005500 #x00002800 #x0000df00
#x00008c00 #x0000a100 #x00008900 #x00000d00 #x0000bf00 #x0000e600 #x00004200 #x00006800
#x00004100 #x00009900 #x00002d00 #x00000f00 #x0000b000 #x00005400 #x0000bb00 #x00001600
))

(define Te4_2 '#(
#x00630000 #x007c0000 #x00770000 #x007b0000 #x00f20000 #x006b0000 #x006f0000 #x00c50000
#x00300000 #x00010000 #x00670000 #x002b0000 #x00fe0000 #x00d70000 #x00ab0000 #x00760000
#x00ca0000 #x00820000 #x00c90000 #x007d0000 #x00fa0000 #x00590000 #x00470000 #x00f00000
#x00ad0000 #x00d40000 #x00a20000 #x00af0000 #x009c0000 #x00a40000 #x00720000 #x00c00000
#x00b70000 #x00fd0000 #x00930000 #x00260000 #x00360000 #x003f0000 #x00f70000 #x00cc0000
#x00340000 #x00a50000 #x00e50000 #x00f10000 #x00710000 #x00d80000 #x00310000 #x00150000
#x00040000 #x00c70000 #x00230000 #x00c30000 #x00180000 #x00960000 #x00050000 #x009a0000
#x00070000 #x00120000 #x00800000 #x00e20000 #x00eb0000 #x00270000 #x00b20000 #x00750000
#x00090000 #x00830000 #x002c0000 #x001a0000 #x001b0000 #x006e0000 #x005a0000 #x00a00000
#x00520000 #x003b0000 #x00d60000 #x00b30000 #x00290000 #x00e30000 #x002f0000 #x00840000
#x00530000 #x00d10000 #x00000000 #x00ed0000 #x00200000 #x00fc0000 #x00b10000 #x005b0000
#x006a0000 #x00cb0000 #x00be0000 #x00390000 #x004a0000 #x004c0000 #x00580000 #x00cf0000
#x00d00000 #x00ef0000 #x00aa0000 #x00fb0000 #x00430000 #x004d0000 #x00330000 #x00850000
#x00450000 #x00f90000 #x00020000 #x007f0000 #x00500000 #x003c0000 #x009f0000 #x00a80000
#x00510000 #x00a30000 #x00400000 #x008f0000 #x00920000 #x009d0000 #x00380000 #x00f50000
#x00bc0000 #x00b60000 #x00da0000 #x00210000 #x00100000 #x00ff0000 #x00f30000 #x00d20000
#x00cd0000 #x000c0000 #x00130000 #x00ec0000 #x005f0000 #x00970000 #x00440000 #x00170000
#x00c40000 #x00a70000 #x007e0000 #x003d0000 #x00640000 #x005d0000 #x00190000 #x00730000
#x00600000 #x00810000 #x004f0000 #x00dc0000 #x00220000 #x002a0000 #x00900000 #x00880000
#x00460000 #x00ee0000 #x00b80000 #x00140000 #x00de0000 #x005e0000 #x000b0000 #x00db0000
#x00e00000 #x00320000 #x003a0000 #x000a0000 #x00490000 #x00060000 #x00240000 #x005c0000
#x00c20000 #x00d30000 #x00ac0000 #x00620000 #x00910000 #x00950000 #x00e40000 #x00790000
#x00e70000 #x00c80000 #x00370000 #x006d0000 #x008d0000 #x00d50000 #x004e0000 #x00a90000
#x006c0000 #x00560000 #x00f40000 #x00ea0000 #x00650000 #x007a0000 #x00ae0000 #x00080000
#x00ba0000 #x00780000 #x00250000 #x002e0000 #x001c0000 #x00a60000 #x00b40000 #x00c60000
#x00e80000 #x00dd0000 #x00740000 #x001f0000 #x004b0000 #x00bd0000 #x008b0000 #x008a0000
#x00700000 #x003e0000 #x00b50000 #x00660000 #x00480000 #x00030000 #x00f60000 #x000e0000
#x00610000 #x00350000 #x00570000 #x00b90000 #x00860000 #x00c10000 #x001d0000 #x009e0000
#x00e10000 #x00f80000 #x00980000 #x00110000 #x00690000 #x00d90000 #x008e0000 #x00940000
#x009b0000 #x001e0000 #x00870000 #x00e90000 #x00ce0000 #x00550000 #x00280000 #x00df0000
#x008c0000 #x00a10000 #x00890000 #x000d0000 #x00bf0000 #x00e60000 #x00420000 #x00680000
#x00410000 #x00990000 #x002d0000 #x000f0000 #x00b00000 #x00540000 #x00bb0000 #x00160000
))

(define Te4_3 '#(
#x63000000 #x7c000000 #x77000000 #x7b000000 #xf2000000 #x6b000000 #x6f000000 #xc5000000
#x30000000 #x01000000 #x67000000 #x2b000000 #xfe000000 #xd7000000 #xab000000 #x76000000
#xca000000 #x82000000 #xc9000000 #x7d000000 #xfa000000 #x59000000 #x47000000 #xf0000000
#xad000000 #xd4000000 #xa2000000 #xaf000000 #x9c000000 #xa4000000 #x72000000 #xc0000000
#xb7000000 #xfd000000 #x93000000 #x26000000 #x36000000 #x3f000000 #xf7000000 #xcc000000
#x34000000 #xa5000000 #xe5000000 #xf1000000 #x71000000 #xd8000000 #x31000000 #x15000000
#x04000000 #xc7000000 #x23000000 #xc3000000 #x18000000 #x96000000 #x05000000 #x9a000000
#x07000000 #x12000000 #x80000000 #xe2000000 #xeb000000 #x27000000 #xb2000000 #x75000000
#x09000000 #x83000000 #x2c000000 #x1a000000 #x1b000000 #x6e000000 #x5a000000 #xa0000000
#x52000000 #x3b000000 #xd6000000 #xb3000000 #x29000000 #xe3000000 #x2f000000 #x84000000
#x53000000 #xd1000000 #x00000000 #xed000000 #x20000000 #xfc000000 #xb1000000 #x5b000000
#x6a000000 #xcb000000 #xbe000000 #x39000000 #x4a000000 #x4c000000 #x58000000 #xcf000000
#xd0000000 #xef000000 #xaa000000 #xfb000000 #x43000000 #x4d000000 #x33000000 #x85000000
#x45000000 #xf9000000 #x02000000 #x7f000000 #x50000000 #x3c000000 #x9f000000 #xa8000000
#x51000000 #xa3000000 #x40000000 #x8f000000 #x92000000 #x9d000000 #x38000000 #xf5000000
#xbc000000 #xb6000000 #xda000000 #x21000000 #x10000000 #xff000000 #xf3000000 #xd2000000
#xcd000000 #x0c000000 #x13000000 #xec000000 #x5f000000 #x97000000 #x44000000 #x17000000
#xc4000000 #xa7000000 #x7e000000 #x3d000000 #x64000000 #x5d000000 #x19000000 #x73000000
#x60000000 #x81000000 #x4f000000 #xdc000000 #x22000000 #x2a000000 #x90000000 #x88000000
#x46000000 #xee000000 #xb8000000 #x14000000 #xde000000 #x5e000000 #x0b000000 #xdb000000
#xe0000000 #x32000000 #x3a000000 #x0a000000 #x49000000 #x06000000 #x24000000 #x5c000000
#xc2000000 #xd3000000 #xac000000 #x62000000 #x91000000 #x95000000 #xe4000000 #x79000000
#xe7000000 #xc8000000 #x37000000 #x6d000000 #x8d000000 #xd5000000 #x4e000000 #xa9000000
#x6c000000 #x56000000 #xf4000000 #xea000000 #x65000000 #x7a000000 #xae000000 #x08000000
#xba000000 #x78000000 #x25000000 #x2e000000 #x1c000000 #xa6000000 #xb4000000 #xc6000000
#xe8000000 #xdd000000 #x74000000 #x1f000000 #x4b000000 #xbd000000 #x8b000000 #x8a000000
#x70000000 #x3e000000 #xb5000000 #x66000000 #x48000000 #x03000000 #xf6000000 #x0e000000
#x61000000 #x35000000 #x57000000 #xb9000000 #x86000000 #xc1000000 #x1d000000 #x9e000000
#xe1000000 #xf8000000 #x98000000 #x11000000 #x69000000 #xd9000000 #x8e000000 #x94000000
#x9b000000 #x1e000000 #x87000000 #xe9000000 #xce000000 #x55000000 #x28000000 #xdf000000
#x8c000000 #xa1000000 #x89000000 #x0d000000 #xbf000000 #xe6000000 #x42000000 #x68000000
#x41000000 #x99000000 #x2d000000 #x0f000000 #xb0000000 #x54000000 #xbb000000 #x16000000
))

;; descirption
(define TD0 '#(
    #x51f4a750 #x7e416553 #x1a17a4c3 #x3a275e96
    #x3bab6bcb #x1f9d45f1 #xacfa58ab #x4be30393
    #x2030fa55 #xad766df6 #x88cc7691 #xf5024c25
    #x4fe5d7fc #xc52acbd7 #x26354480 #xb562a38f
    #xdeb15a49 #x25ba1b67 #x45ea0e98 #x5dfec0e1
    #xc32f7502 #x814cf012 #x8d4697a3 #x6bd3f9c6
    #x038f5fe7 #x15929c95 #xbf6d7aeb #x955259da
    #xd4be832d #x587421d3 #x49e06929 #x8ec9c844
    #x75c2896a #xf48e7978 #x99583e6b #x27b971dd
    #xbee14fb6 #xf088ad17 #xc920ac66 #x7dce3ab4
    #x63df4a18 #xe51a3182 #x97513360 #x62537f45
    #xb16477e0 #xbb6bae84 #xfe81a01c #xf9082b94
    #x70486858 #x8f45fd19 #x94de6c87 #x527bf8b7
    #xab73d323 #x724b02e2 #xe31f8f57 #x6655ab2a
    #xb2eb2807 #x2fb5c203 #x86c57b9a #xd33708a5
    #x302887f2 #x23bfa5b2 #x02036aba #xed16825c
    #x8acf1c2b #xa779b492 #xf307f2f0 #x4e69e2a1
    #x65daf4cd #x0605bed5 #xd134621f #xc4a6fe8a
    #x342e539d #xa2f355a0 #x058ae132 #xa4f6eb75
    #x0b83ec39 #x4060efaa #x5e719f06 #xbd6e1051
    #x3e218af9 #x96dd063d #xdd3e05ae #x4de6bd46
    #x91548db5 #x71c45d05 #x0406d46f #x605015ff
    #x1998fb24 #xd6bde997 #x894043cc #x67d99e77
    #xb0e842bd #x07898b88 #xe7195b38 #x79c8eedb
    #xa17c0a47 #x7c420fe9 #xf8841ec9 #x00000000
    #x09808683 #x322bed48 #x1e1170ac #x6c5a724e
    #xfd0efffb #x0f853856 #x3daed51e #x362d3927
    #x0a0fd964 #x685ca621 #x9b5b54d1 #x24362e3a
    #x0c0a67b1 #x9357e70f #xb4ee96d2 #x1b9b919e
    #x80c0c54f #x61dc20a2 #x5a774b69 #x1c121a16
    #xe293ba0a #xc0a02ae5 #x3c22e043 #x121b171d
    #x0e090d0b #xf28bc7ad #x2db6a8b9 #x141ea9c8
    #x57f11985 #xaf75074c #xee99ddbb #xa37f60fd
    #xf701269f #x5c72f5bc #x44663bc5 #x5bfb7e34
    #x8b432976 #xcb23c6dc #xb6edfc68 #xb8e4f163
    #xd731dcca #x42638510 #x13972240 #x84c61120
    #x854a247d #xd2bb3df8 #xaef93211 #xc729a16d
    #x1d9e2f4b #xdcb230f3 #x0d8652ec #x77c1e3d0
    #x2bb3166c #xa970b999 #x119448fa #x47e96422
    #xa8fc8cc4 #xa0f03f1a #x567d2cd8 #x223390ef
    #x87494ec7 #xd938d1c1 #x8ccaa2fe #x98d40b36
    #xa6f581cf #xa57ade28 #xdab78e26 #x3fadbfa4
    #x2c3a9de4 #x5078920d #x6a5fcc9b #x547e4662
    #xf68d13c2 #x90d8b8e8 #x2e39f75e #x82c3aff5
    #x9f5d80be #x69d0937c #x6fd52da9 #xcf2512b3
    #xc8ac993b #x10187da7 #xe89c636e #xdb3bbb7b
    #xcd267809 #x6e5918f4 #xec9ab701 #x834f9aa8
    #xe6956e65 #xaaffe67e #x21bccf08 #xef15e8e6
    #xbae79bd9 #x4a6f36ce #xea9f09d4 #x29b07cd6
    #x31a4b2af #x2a3f2331 #xc6a59430 #x35a266c0
    #x744ebc37 #xfc82caa6 #xe090d0b0 #x33a7d815
    #xf104984a #x41ecdaf7 #x7fcd500e #x1791f62f
    #x764dd68d #x43efb04d #xccaa4d54 #xe49604df
    #x9ed1b5e3 #x4c6a881b #xc12c1fb8 #x4665517f
    #x9d5eea04 #x018c355d #xfa877473 #xfb0b412e
    #xb3671d5a #x92dbd252 #xe9105633 #x6dd64713
    #x9ad7618c #x37a10c7a #x59f8148e #xeb133c89
    #xcea927ee #xb761c935 #xe11ce5ed #x7a47b13c
    #x9cd2df59 #x55f2733f #x1814ce79 #x73c737bf
    #x53f7cdea #x5ffdaa5b #xdf3d6f14 #x7844db86
    #xcaaff381 #xb968c43e #x3824342c #xc2a3405f
    #x161dc372 #xbce2250c #x283c498b #xff0d9541
    #x39a80171 #x080cb3de #xd8b4e49c #x6456c190
    #x7bcb8461 #xd532b670 #x486c5c74 #xd0b85742
))

(define Td4 '#(
    #x52525252 #x09090909 #x6a6a6a6a #xd5d5d5d5
    #x30303030 #x36363636 #xa5a5a5a5 #x38383838
    #xbfbfbfbf #x40404040 #xa3a3a3a3 #x9e9e9e9e
    #x81818181 #xf3f3f3f3 #xd7d7d7d7 #xfbfbfbfb
    #x7c7c7c7c #xe3e3e3e3 #x39393939 #x82828282
    #x9b9b9b9b #x2f2f2f2f #xffffffff #x87878787
    #x34343434 #x8e8e8e8e #x43434343 #x44444444
    #xc4c4c4c4 #xdededede #xe9e9e9e9 #xcbcbcbcb
    #x54545454 #x7b7b7b7b #x94949494 #x32323232
    #xa6a6a6a6 #xc2c2c2c2 #x23232323 #x3d3d3d3d
    #xeeeeeeee #x4c4c4c4c #x95959595 #x0b0b0b0b
    #x42424242 #xfafafafa #xc3c3c3c3 #x4e4e4e4e
    #x08080808 #x2e2e2e2e #xa1a1a1a1 #x66666666
    #x28282828 #xd9d9d9d9 #x24242424 #xb2b2b2b2
    #x76767676 #x5b5b5b5b #xa2a2a2a2 #x49494949
    #x6d6d6d6d #x8b8b8b8b #xd1d1d1d1 #x25252525
    #x72727272 #xf8f8f8f8 #xf6f6f6f6 #x64646464
    #x86868686 #x68686868 #x98989898 #x16161616
    #xd4d4d4d4 #xa4a4a4a4 #x5c5c5c5c #xcccccccc
    #x5d5d5d5d #x65656565 #xb6b6b6b6 #x92929292
    #x6c6c6c6c #x70707070 #x48484848 #x50505050
    #xfdfdfdfd #xedededed #xb9b9b9b9 #xdadadada
    #x5e5e5e5e #x15151515 #x46464646 #x57575757
    #xa7a7a7a7 #x8d8d8d8d #x9d9d9d9d #x84848484
    #x90909090 #xd8d8d8d8 #xabababab #x00000000
    #x8c8c8c8c #xbcbcbcbc #xd3d3d3d3 #x0a0a0a0a
    #xf7f7f7f7 #xe4e4e4e4 #x58585858 #x05050505
    #xb8b8b8b8 #xb3b3b3b3 #x45454545 #x06060606
    #xd0d0d0d0 #x2c2c2c2c #x1e1e1e1e #x8f8f8f8f
    #xcacacaca #x3f3f3f3f #x0f0f0f0f #x02020202
    #xc1c1c1c1 #xafafafaf #xbdbdbdbd #x03030303
    #x01010101 #x13131313 #x8a8a8a8a #x6b6b6b6b
    #x3a3a3a3a #x91919191 #x11111111 #x41414141
    #x4f4f4f4f #x67676767 #xdcdcdcdc #xeaeaeaea
    #x97979797 #xf2f2f2f2 #xcfcfcfcf #xcececece
    #xf0f0f0f0 #xb4b4b4b4 #xe6e6e6e6 #x73737373
    #x96969696 #xacacacac #x74747474 #x22222222
    #xe7e7e7e7 #xadadadad #x35353535 #x85858585
    #xe2e2e2e2 #xf9f9f9f9 #x37373737 #xe8e8e8e8
    #x1c1c1c1c #x75757575 #xdfdfdfdf #x6e6e6e6e
    #x47474747 #xf1f1f1f1 #x1a1a1a1a #x71717171
    #x1d1d1d1d #x29292929 #xc5c5c5c5 #x89898989
    #x6f6f6f6f #xb7b7b7b7 #x62626262 #x0e0e0e0e
    #xaaaaaaaa #x18181818 #xbebebebe #x1b1b1b1b
    #xfcfcfcfc #x56565656 #x3e3e3e3e #x4b4b4b4b
    #xc6c6c6c6 #xd2d2d2d2 #x79797979 #x20202020
    #x9a9a9a9a #xdbdbdbdb #xc0c0c0c0 #xfefefefe
    #x78787878 #xcdcdcdcd #x5a5a5a5a #xf4f4f4f4
    #x1f1f1f1f #xdddddddd #xa8a8a8a8 #x33333333
    #x88888888 #x07070707 #xc7c7c7c7 #x31313131
    #xb1b1b1b1 #x12121212 #x10101010 #x59595959
    #x27272727 #x80808080 #xecececec #x5f5f5f5f
    #x60606060 #x51515151 #x7f7f7f7f #xa9a9a9a9
    #x19191919 #xb5b5b5b5 #x4a4a4a4a #x0d0d0d0d
    #x2d2d2d2d #xe5e5e5e5 #x7a7a7a7a #x9f9f9f9f
    #x93939393 #xc9c9c9c9 #x9c9c9c9c #xefefefef
    #xa0a0a0a0 #xe0e0e0e0 #x3b3b3b3b #x4d4d4d4d
    #xaeaeaeae #x2a2a2a2a #xf5f5f5f5 #xb0b0b0b0
    #xc8c8c8c8 #xebebebeb #xbbbbbbbb #x3c3c3c3c
    #x83838383 #x53535353 #x99999999 #x61616161
    #x17171717 #x2b2b2b2b #x04040404 #x7e7e7e7e
    #xbabababa #x77777777 #xd6d6d6d6 #x26262626
    #xe1e1e1e1 #x69696969 #x14141414 #x63636363
    #x55555555 #x21212121 #x0c0c0c0c #x7d7d7d7d
))

(define TD1 '#(
    #x5051f4a7 #x537e4165 #xc31a17a4 #x963a275e
    #xcb3bab6b #xf11f9d45 #xabacfa58 #x934be303
    #x552030fa #xf6ad766d #x9188cc76 #x25f5024c
    #xfc4fe5d7 #xd7c52acb #x80263544 #x8fb562a3
    #x49deb15a #x6725ba1b #x9845ea0e #xe15dfec0
    #x02c32f75 #x12814cf0 #xa38d4697 #xc66bd3f9
    #xe7038f5f #x9515929c #xebbf6d7a #xda955259
    #x2dd4be83 #xd3587421 #x2949e069 #x448ec9c8
    #x6a75c289 #x78f48e79 #x6b99583e #xdd27b971
    #xb6bee14f #x17f088ad #x66c920ac #xb47dce3a
    #x1863df4a #x82e51a31 #x60975133 #x4562537f
    #xe0b16477 #x84bb6bae #x1cfe81a0 #x94f9082b
    #x58704868 #x198f45fd #x8794de6c #xb7527bf8
    #x23ab73d3 #xe2724b02 #x57e31f8f #x2a6655ab
    #x07b2eb28 #x032fb5c2 #x9a86c57b #xa5d33708
    #xf2302887 #xb223bfa5 #xba02036a #x5ced1682
    #x2b8acf1c #x92a779b4 #xf0f307f2 #xa14e69e2
    #xcd65daf4 #xd50605be #x1fd13462 #x8ac4a6fe
    #x9d342e53 #xa0a2f355 #x32058ae1 #x75a4f6eb
    #x390b83ec #xaa4060ef #x065e719f #x51bd6e10
    #xf93e218a #x3d96dd06 #xaedd3e05 #x464de6bd
    #xb591548d #x0571c45d #x6f0406d4 #xff605015
    #x241998fb #x97d6bde9 #xcc894043 #x7767d99e
    #xbdb0e842 #x8807898b #x38e7195b #xdb79c8ee
    #x47a17c0a #xe97c420f #xc9f8841e #x00000000
    #x83098086 #x48322bed #xac1e1170 #x4e6c5a72
    #xfbfd0eff #x560f8538 #x1e3daed5 #x27362d39
    #x640a0fd9 #x21685ca6 #xd19b5b54 #x3a24362e
    #xb10c0a67 #x0f9357e7 #xd2b4ee96 #x9e1b9b91
    #x4f80c0c5 #xa261dc20 #x695a774b #x161c121a
    #x0ae293ba #xe5c0a02a #x433c22e0 #x1d121b17
    #x0b0e090d #xadf28bc7 #xb92db6a8 #xc8141ea9
    #x8557f119 #x4caf7507 #xbbee99dd #xfda37f60
    #x9ff70126 #xbc5c72f5 #xc544663b #x345bfb7e
    #x768b4329 #xdccb23c6 #x68b6edfc #x63b8e4f1
    #xcad731dc #x10426385 #x40139722 #x2084c611
    #x7d854a24 #xf8d2bb3d #x11aef932 #x6dc729a1
    #x4b1d9e2f #xf3dcb230 #xec0d8652 #xd077c1e3
    #x6c2bb316 #x99a970b9 #xfa119448 #x2247e964
    #xc4a8fc8c #x1aa0f03f #xd8567d2c #xef223390
    #xc787494e #xc1d938d1 #xfe8ccaa2 #x3698d40b
    #xcfa6f581 #x28a57ade #x26dab78e #xa43fadbf
    #xe42c3a9d #x0d507892 #x9b6a5fcc #x62547e46
    #xc2f68d13 #xe890d8b8 #x5e2e39f7 #xf582c3af
    #xbe9f5d80 #x7c69d093 #xa96fd52d #xb3cf2512
    #x3bc8ac99 #xa710187d #x6ee89c63 #x7bdb3bbb
    #x09cd2678 #xf46e5918 #x01ec9ab7 #xa8834f9a
    #x65e6956e #x7eaaffe6 #x0821bccf #xe6ef15e8
    #xd9bae79b #xce4a6f36 #xd4ea9f09 #xd629b07c
    #xaf31a4b2 #x312a3f23 #x30c6a594 #xc035a266
    #x37744ebc #xa6fc82ca #xb0e090d0 #x1533a7d8
    #x4af10498 #xf741ecda #x0e7fcd50 #x2f1791f6
    #x8d764dd6 #x4d43efb0 #x54ccaa4d #xdfe49604
    #xe39ed1b5 #x1b4c6a88 #xb8c12c1f #x7f466551
    #x049d5eea #x5d018c35 #x73fa8774 #x2efb0b41
    #x5ab3671d #x5292dbd2 #x33e91056 #x136dd647
    #x8c9ad761 #x7a37a10c #x8e59f814 #x89eb133c
    #xeecea927 #x35b761c9 #xede11ce5 #x3c7a47b1
    #x599cd2df #x3f55f273 #x791814ce #xbf73c737
    #xea53f7cd #x5b5ffdaa #x14df3d6f #x867844db
    #x81caaff3 #x3eb968c4 #x2c382434 #x5fc2a340
    #x72161dc3 #x0cbce225 #x8b283c49 #x41ff0d95
    #x7139a801 #xde080cb3 #x9cd8b4e4 #x906456c1
    #x617bcb84 #x70d532b6 #x74486c5c #x42d0b857
))
(define TD2 '#(
    #xa75051f4 #x65537e41 #xa4c31a17 #x5e963a27
    #x6bcb3bab #x45f11f9d #x58abacfa #x03934be3
    #xfa552030 #x6df6ad76 #x769188cc #x4c25f502
    #xd7fc4fe5 #xcbd7c52a #x44802635 #xa38fb562
    #x5a49deb1 #x1b6725ba #x0e9845ea #xc0e15dfe
    #x7502c32f #xf012814c #x97a38d46 #xf9c66bd3
    #x5fe7038f #x9c951592 #x7aebbf6d #x59da9552
    #x832dd4be #x21d35874 #x692949e0 #xc8448ec9
    #x896a75c2 #x7978f48e #x3e6b9958 #x71dd27b9
    #x4fb6bee1 #xad17f088 #xac66c920 #x3ab47dce
    #x4a1863df #x3182e51a #x33609751 #x7f456253
    #x77e0b164 #xae84bb6b #xa01cfe81 #x2b94f908
    #x68587048 #xfd198f45 #x6c8794de #xf8b7527b
    #xd323ab73 #x02e2724b #x8f57e31f #xab2a6655
    #x2807b2eb #xc2032fb5 #x7b9a86c5 #x08a5d337
    #x87f23028 #xa5b223bf #x6aba0203 #x825ced16
    #x1c2b8acf #xb492a779 #xf2f0f307 #xe2a14e69
    #xf4cd65da #xbed50605 #x621fd134 #xfe8ac4a6
    #x539d342e #x55a0a2f3 #xe132058a #xeb75a4f6
    #xec390b83 #xefaa4060 #x9f065e71 #x1051bd6e
    #x8af93e21 #x063d96dd #x05aedd3e #xbd464de6
    #x8db59154 #x5d0571c4 #xd46f0406 #x15ff6050
    #xfb241998 #xe997d6bd #x43cc8940 #x9e7767d9
    #x42bdb0e8 #x8b880789 #x5b38e719 #xeedb79c8
    #x0a47a17c #x0fe97c42 #x1ec9f884 #x00000000
    #x86830980 #xed48322b #x70ac1e11 #x724e6c5a
    #xfffbfd0e #x38560f85 #xd51e3dae #x3927362d
    #xd9640a0f #xa621685c #x54d19b5b #x2e3a2436
    #x67b10c0a #xe70f9357 #x96d2b4ee #x919e1b9b
    #xc54f80c0 #x20a261dc #x4b695a77 #x1a161c12
    #xba0ae293 #x2ae5c0a0 #xe0433c22 #x171d121b
    #x0d0b0e09 #xc7adf28b #xa8b92db6 #xa9c8141e
    #x198557f1 #x074caf75 #xddbbee99 #x60fda37f
    #x269ff701 #xf5bc5c72 #x3bc54466 #x7e345bfb
    #x29768b43 #xc6dccb23 #xfc68b6ed #xf163b8e4
    #xdccad731 #x85104263 #x22401397 #x112084c6
    #x247d854a #x3df8d2bb #x3211aef9 #xa16dc729
    #x2f4b1d9e #x30f3dcb2 #x52ec0d86 #xe3d077c1
    #x166c2bb3 #xb999a970 #x48fa1194 #x642247e9
    #x8cc4a8fc #x3f1aa0f0 #x2cd8567d #x90ef2233
    #x4ec78749 #xd1c1d938 #xa2fe8cca #x0b3698d4
    #x81cfa6f5 #xde28a57a #x8e26dab7 #xbfa43fad
    #x9de42c3a #x920d5078 #xcc9b6a5f #x4662547e
    #x13c2f68d #xb8e890d8 #xf75e2e39 #xaff582c3
    #x80be9f5d #x937c69d0 #x2da96fd5 #x12b3cf25
    #x993bc8ac #x7da71018 #x636ee89c #xbb7bdb3b
    #x7809cd26 #x18f46e59 #xb701ec9a #x9aa8834f
    #x6e65e695 #xe67eaaff #xcf0821bc #xe8e6ef15
    #x9bd9bae7 #x36ce4a6f #x09d4ea9f #x7cd629b0
    #xb2af31a4 #x23312a3f #x9430c6a5 #x66c035a2
    #xbc37744e #xcaa6fc82 #xd0b0e090 #xd81533a7
    #x984af104 #xdaf741ec #x500e7fcd #xf62f1791
    #xd68d764d #xb04d43ef #x4d54ccaa #x04dfe496
    #xb5e39ed1 #x881b4c6a #x1fb8c12c #x517f4665
    #xea049d5e #x355d018c #x7473fa87 #x412efb0b
    #x1d5ab367 #xd25292db #x5633e910 #x47136dd6
    #x618c9ad7 #x0c7a37a1 #x148e59f8 #x3c89eb13
    #x27eecea9 #xc935b761 #xe5ede11c #xb13c7a47
    #xdf599cd2 #x733f55f2 #xce791814 #x37bf73c7
    #xcdea53f7 #xaa5b5ffd #x6f14df3d #xdb867844
    #xf381caaf #xc43eb968 #x342c3824 #x405fc2a3
    #xc372161d #x250cbce2 #x498b283c #x9541ff0d
    #x017139a8 #xb3de080c #xe49cd8b4 #xc1906456
    #x84617bcb #xb670d532 #x5c74486c #x5742d0b8
))
(define TD3 '#(
    #xf4a75051 #x4165537e #x17a4c31a #x275e963a
    #xab6bcb3b #x9d45f11f #xfa58abac #xe303934b
    #x30fa5520 #x766df6ad #xcc769188 #x024c25f5
    #xe5d7fc4f #x2acbd7c5 #x35448026 #x62a38fb5
    #xb15a49de #xba1b6725 #xea0e9845 #xfec0e15d
    #x2f7502c3 #x4cf01281 #x4697a38d #xd3f9c66b
    #x8f5fe703 #x929c9515 #x6d7aebbf #x5259da95
    #xbe832dd4 #x7421d358 #xe0692949 #xc9c8448e
    #xc2896a75 #x8e7978f4 #x583e6b99 #xb971dd27
    #xe14fb6be #x88ad17f0 #x20ac66c9 #xce3ab47d
    #xdf4a1863 #x1a3182e5 #x51336097 #x537f4562
    #x6477e0b1 #x6bae84bb #x81a01cfe #x082b94f9
    #x48685870 #x45fd198f #xde6c8794 #x7bf8b752
    #x73d323ab #x4b02e272 #x1f8f57e3 #x55ab2a66
    #xeb2807b2 #xb5c2032f #xc57b9a86 #x3708a5d3
    #x2887f230 #xbfa5b223 #x036aba02 #x16825ced
    #xcf1c2b8a #x79b492a7 #x07f2f0f3 #x69e2a14e
    #xdaf4cd65 #x05bed506 #x34621fd1 #xa6fe8ac4
    #x2e539d34 #xf355a0a2 #x8ae13205 #xf6eb75a4
    #x83ec390b #x60efaa40 #x719f065e #x6e1051bd
    #x218af93e #xdd063d96 #x3e05aedd #xe6bd464d
    #x548db591 #xc45d0571 #x06d46f04 #x5015ff60
    #x98fb2419 #xbde997d6 #x4043cc89 #xd99e7767
    #xe842bdb0 #x898b8807 #x195b38e7 #xc8eedb79
    #x7c0a47a1 #x420fe97c #x841ec9f8 #x00000000
    #x80868309 #x2bed4832 #x1170ac1e #x5a724e6c
    #x0efffbfd #x8538560f #xaed51e3d #x2d392736
    #x0fd9640a #x5ca62168 #x5b54d19b #x362e3a24
    #x0a67b10c #x57e70f93 #xee96d2b4 #x9b919e1b
    #xc0c54f80 #xdc20a261 #x774b695a #x121a161c
    #x93ba0ae2 #xa02ae5c0 #x22e0433c #x1b171d12
    #x090d0b0e #x8bc7adf2 #xb6a8b92d #x1ea9c814
    #xf1198557 #x75074caf #x99ddbbee #x7f60fda3
    #x01269ff7 #x72f5bc5c #x663bc544 #xfb7e345b
    #x4329768b #x23c6dccb #xedfc68b6 #xe4f163b8
    #x31dccad7 #x63851042 #x97224013 #xc6112084
    #x4a247d85 #xbb3df8d2 #xf93211ae #x29a16dc7
    #x9e2f4b1d #xb230f3dc #x8652ec0d #xc1e3d077
    #xb3166c2b #x70b999a9 #x9448fa11 #xe9642247
    #xfc8cc4a8 #xf03f1aa0 #x7d2cd856 #x3390ef22
    #x494ec787 #x38d1c1d9 #xcaa2fe8c #xd40b3698
    #xf581cfa6 #x7ade28a5 #xb78e26da #xadbfa43f
    #x3a9de42c #x78920d50 #x5fcc9b6a #x7e466254
    #x8d13c2f6 #xd8b8e890 #x39f75e2e #xc3aff582
    #x5d80be9f #xd0937c69 #xd52da96f #x2512b3cf
    #xac993bc8 #x187da710 #x9c636ee8 #x3bbb7bdb
    #x267809cd #x5918f46e #x9ab701ec #x4f9aa883
    #x956e65e6 #xffe67eaa #xbccf0821 #x15e8e6ef
    #xe79bd9ba #x6f36ce4a #x9f09d4ea #xb07cd629
    #xa4b2af31 #x3f23312a #xa59430c6 #xa266c035
    #x4ebc3774 #x82caa6fc #x90d0b0e0 #xa7d81533
    #x04984af1 #xecdaf741 #xcd500e7f #x91f62f17
    #x4dd68d76 #xefb04d43 #xaa4d54cc #x9604dfe4
    #xd1b5e39e #x6a881b4c #x2c1fb8c1 #x65517f46
    #x5eea049d #x8c355d01 #x877473fa #x0b412efb
    #x671d5ab3 #xdbd25292 #x105633e9 #xd647136d
    #xd7618c9a #xa10c7a37 #xf8148e59 #x133c89eb
    #xa927eece #x61c935b7 #x1ce5ede1 #x47b13c7a
    #xd2df599c #xf2733f55 #x14ce7918 #xc737bf73
    #xf7cdea53 #xfdaa5b5f #x3d6f14df #x44db8678
    #xaff381ca #x68c43eb9 #x24342c38 #xa3405fc2
    #x1dc37216 #xe2250cbc #x3c498b28 #x0d9541ff
    #xa8017139 #x0cb3de08 #xb4e49cd8 #x56c19064
    #xcb84617b #x32b670d5 #x6c5c7448 #xb85742d0
))

(define Tks0 '#(
#x00000000 #x0e090d0b #x1c121a16 #x121b171d #x3824342c #x362d3927 #x24362e3a #x2a3f2331
#x70486858 #x7e416553 #x6c5a724e #x62537f45 #x486c5c74 #x4665517f #x547e4662 #x5a774b69
#xe090d0b0 #xee99ddbb #xfc82caa6 #xf28bc7ad #xd8b4e49c #xd6bde997 #xc4a6fe8a #xcaaff381
#x90d8b8e8 #x9ed1b5e3 #x8ccaa2fe #x82c3aff5 #xa8fc8cc4 #xa6f581cf #xb4ee96d2 #xbae79bd9
#xdb3bbb7b #xd532b670 #xc729a16d #xc920ac66 #xe31f8f57 #xed16825c #xff0d9541 #xf104984a
#xab73d323 #xa57ade28 #xb761c935 #xb968c43e #x9357e70f #x9d5eea04 #x8f45fd19 #x814cf012
#x3bab6bcb #x35a266c0 #x27b971dd #x29b07cd6 #x038f5fe7 #x0d8652ec #x1f9d45f1 #x119448fa
#x4be30393 #x45ea0e98 #x57f11985 #x59f8148e #x73c737bf #x7dce3ab4 #x6fd52da9 #x61dc20a2
#xad766df6 #xa37f60fd #xb16477e0 #xbf6d7aeb #x955259da #x9b5b54d1 #x894043cc #x87494ec7
#xdd3e05ae #xd33708a5 #xc12c1fb8 #xcf2512b3 #xe51a3182 #xeb133c89 #xf9082b94 #xf701269f
#x4de6bd46 #x43efb04d #x51f4a750 #x5ffdaa5b #x75c2896a #x7bcb8461 #x69d0937c #x67d99e77
#x3daed51e #x33a7d815 #x21bccf08 #x2fb5c203 #x058ae132 #x0b83ec39 #x1998fb24 #x1791f62f
#x764dd68d #x7844db86 #x6a5fcc9b #x6456c190 #x4e69e2a1 #x4060efaa #x527bf8b7 #x5c72f5bc
#x0605bed5 #x080cb3de #x1a17a4c3 #x141ea9c8 #x3e218af9 #x302887f2 #x223390ef #x2c3a9de4
#x96dd063d #x98d40b36 #x8acf1c2b #x84c61120 #xaef93211 #xa0f03f1a #xb2eb2807 #xbce2250c
#xe6956e65 #xe89c636e #xfa877473 #xf48e7978 #xdeb15a49 #xd0b85742 #xc2a3405f #xccaa4d54
#x41ecdaf7 #x4fe5d7fc #x5dfec0e1 #x53f7cdea #x79c8eedb #x77c1e3d0 #x65daf4cd #x6bd3f9c6
#x31a4b2af #x3fadbfa4 #x2db6a8b9 #x23bfa5b2 #x09808683 #x07898b88 #x15929c95 #x1b9b919e
#xa17c0a47 #xaf75074c #xbd6e1051 #xb3671d5a #x99583e6b #x97513360 #x854a247d #x8b432976
#xd134621f #xdf3d6f14 #xcd267809 #xc32f7502 #xe9105633 #xe7195b38 #xf5024c25 #xfb0b412e
#x9ad7618c #x94de6c87 #x86c57b9a #x88cc7691 #xa2f355a0 #xacfa58ab #xbee14fb6 #xb0e842bd
#xea9f09d4 #xe49604df #xf68d13c2 #xf8841ec9 #xd2bb3df8 #xdcb230f3 #xcea927ee #xc0a02ae5
#x7a47b13c #x744ebc37 #x6655ab2a #x685ca621 #x42638510 #x4c6a881b #x5e719f06 #x5078920d
#x0a0fd964 #x0406d46f #x161dc372 #x1814ce79 #x322bed48 #x3c22e043 #x2e39f75e #x2030fa55
#xec9ab701 #xe293ba0a #xf088ad17 #xfe81a01c #xd4be832d #xdab78e26 #xc8ac993b #xc6a59430
#x9cd2df59 #x92dbd252 #x80c0c54f #x8ec9c844 #xa4f6eb75 #xaaffe67e #xb8e4f163 #xb6edfc68
#x0c0a67b1 #x02036aba #x10187da7 #x1e1170ac #x342e539d #x3a275e96 #x283c498b #x26354480
#x7c420fe9 #x724b02e2 #x605015ff #x6e5918f4 #x44663bc5 #x4a6f36ce #x587421d3 #x567d2cd8
#x37a10c7a #x39a80171 #x2bb3166c #x25ba1b67 #x0f853856 #x018c355d #x13972240 #x1d9e2f4b
#x47e96422 #x49e06929 #x5bfb7e34 #x55f2733f #x7fcd500e #x71c45d05 #x63df4a18 #x6dd64713
#xd731dcca #xd938d1c1 #xcb23c6dc #xc52acbd7 #xef15e8e6 #xe11ce5ed #xf307f2f0 #xfd0efffb
#xa779b492 #xa970b999 #xbb6bae84 #xb562a38f #x9f5d80be #x91548db5 #x834f9aa8 #x8d4697a3
))

(define Tks1 '#(
#x00000000 #x0b0e090d #x161c121a #x1d121b17 #x2c382434 #x27362d39 #x3a24362e #x312a3f23
#x58704868 #x537e4165 #x4e6c5a72 #x4562537f #x74486c5c #x7f466551 #x62547e46 #x695a774b
#xb0e090d0 #xbbee99dd #xa6fc82ca #xadf28bc7 #x9cd8b4e4 #x97d6bde9 #x8ac4a6fe #x81caaff3
#xe890d8b8 #xe39ed1b5 #xfe8ccaa2 #xf582c3af #xc4a8fc8c #xcfa6f581 #xd2b4ee96 #xd9bae79b
#x7bdb3bbb #x70d532b6 #x6dc729a1 #x66c920ac #x57e31f8f #x5ced1682 #x41ff0d95 #x4af10498
#x23ab73d3 #x28a57ade #x35b761c9 #x3eb968c4 #x0f9357e7 #x049d5eea #x198f45fd #x12814cf0
#xcb3bab6b #xc035a266 #xdd27b971 #xd629b07c #xe7038f5f #xec0d8652 #xf11f9d45 #xfa119448
#x934be303 #x9845ea0e #x8557f119 #x8e59f814 #xbf73c737 #xb47dce3a #xa96fd52d #xa261dc20
#xf6ad766d #xfda37f60 #xe0b16477 #xebbf6d7a #xda955259 #xd19b5b54 #xcc894043 #xc787494e
#xaedd3e05 #xa5d33708 #xb8c12c1f #xb3cf2512 #x82e51a31 #x89eb133c #x94f9082b #x9ff70126
#x464de6bd #x4d43efb0 #x5051f4a7 #x5b5ffdaa #x6a75c289 #x617bcb84 #x7c69d093 #x7767d99e
#x1e3daed5 #x1533a7d8 #x0821bccf #x032fb5c2 #x32058ae1 #x390b83ec #x241998fb #x2f1791f6
#x8d764dd6 #x867844db #x9b6a5fcc #x906456c1 #xa14e69e2 #xaa4060ef #xb7527bf8 #xbc5c72f5
#xd50605be #xde080cb3 #xc31a17a4 #xc8141ea9 #xf93e218a #xf2302887 #xef223390 #xe42c3a9d
#x3d96dd06 #x3698d40b #x2b8acf1c #x2084c611 #x11aef932 #x1aa0f03f #x07b2eb28 #x0cbce225
#x65e6956e #x6ee89c63 #x73fa8774 #x78f48e79 #x49deb15a #x42d0b857 #x5fc2a340 #x54ccaa4d
#xf741ecda #xfc4fe5d7 #xe15dfec0 #xea53f7cd #xdb79c8ee #xd077c1e3 #xcd65daf4 #xc66bd3f9
#xaf31a4b2 #xa43fadbf #xb92db6a8 #xb223bfa5 #x83098086 #x8807898b #x9515929c #x9e1b9b91
#x47a17c0a #x4caf7507 #x51bd6e10 #x5ab3671d #x6b99583e #x60975133 #x7d854a24 #x768b4329
#x1fd13462 #x14df3d6f #x09cd2678 #x02c32f75 #x33e91056 #x38e7195b #x25f5024c #x2efb0b41
#x8c9ad761 #x8794de6c #x9a86c57b #x9188cc76 #xa0a2f355 #xabacfa58 #xb6bee14f #xbdb0e842
#xd4ea9f09 #xdfe49604 #xc2f68d13 #xc9f8841e #xf8d2bb3d #xf3dcb230 #xeecea927 #xe5c0a02a
#x3c7a47b1 #x37744ebc #x2a6655ab #x21685ca6 #x10426385 #x1b4c6a88 #x065e719f #x0d507892
#x640a0fd9 #x6f0406d4 #x72161dc3 #x791814ce #x48322bed #x433c22e0 #x5e2e39f7 #x552030fa
#x01ec9ab7 #x0ae293ba #x17f088ad #x1cfe81a0 #x2dd4be83 #x26dab78e #x3bc8ac99 #x30c6a594
#x599cd2df #x5292dbd2 #x4f80c0c5 #x448ec9c8 #x75a4f6eb #x7eaaffe6 #x63b8e4f1 #x68b6edfc
#xb10c0a67 #xba02036a #xa710187d #xac1e1170 #x9d342e53 #x963a275e #x8b283c49 #x80263544
#xe97c420f #xe2724b02 #xff605015 #xf46e5918 #xc544663b #xce4a6f36 #xd3587421 #xd8567d2c
#x7a37a10c #x7139a801 #x6c2bb316 #x6725ba1b #x560f8538 #x5d018c35 #x40139722 #x4b1d9e2f
#x2247e964 #x2949e069 #x345bfb7e #x3f55f273 #x0e7fcd50 #x0571c45d #x1863df4a #x136dd647
#xcad731dc #xc1d938d1 #xdccb23c6 #xd7c52acb #xe6ef15e8 #xede11ce5 #xf0f307f2 #xfbfd0eff
#x92a779b4 #x99a970b9 #x84bb6bae #x8fb562a3 #xbe9f5d80 #xb591548d #xa8834f9a #xa38d4697
))

(define Tks2 '#(
#x00000000 #x0d0b0e09 #x1a161c12 #x171d121b #x342c3824 #x3927362d #x2e3a2436 #x23312a3f
#x68587048 #x65537e41 #x724e6c5a #x7f456253 #x5c74486c #x517f4665 #x4662547e #x4b695a77
#xd0b0e090 #xddbbee99 #xcaa6fc82 #xc7adf28b #xe49cd8b4 #xe997d6bd #xfe8ac4a6 #xf381caaf
#xb8e890d8 #xb5e39ed1 #xa2fe8cca #xaff582c3 #x8cc4a8fc #x81cfa6f5 #x96d2b4ee #x9bd9bae7
#xbb7bdb3b #xb670d532 #xa16dc729 #xac66c920 #x8f57e31f #x825ced16 #x9541ff0d #x984af104
#xd323ab73 #xde28a57a #xc935b761 #xc43eb968 #xe70f9357 #xea049d5e #xfd198f45 #xf012814c
#x6bcb3bab #x66c035a2 #x71dd27b9 #x7cd629b0 #x5fe7038f #x52ec0d86 #x45f11f9d #x48fa1194
#x03934be3 #x0e9845ea #x198557f1 #x148e59f8 #x37bf73c7 #x3ab47dce #x2da96fd5 #x20a261dc
#x6df6ad76 #x60fda37f #x77e0b164 #x7aebbf6d #x59da9552 #x54d19b5b #x43cc8940 #x4ec78749
#x05aedd3e #x08a5d337 #x1fb8c12c #x12b3cf25 #x3182e51a #x3c89eb13 #x2b94f908 #x269ff701
#xbd464de6 #xb04d43ef #xa75051f4 #xaa5b5ffd #x896a75c2 #x84617bcb #x937c69d0 #x9e7767d9
#xd51e3dae #xd81533a7 #xcf0821bc #xc2032fb5 #xe132058a #xec390b83 #xfb241998 #xf62f1791
#xd68d764d #xdb867844 #xcc9b6a5f #xc1906456 #xe2a14e69 #xefaa4060 #xf8b7527b #xf5bc5c72
#xbed50605 #xb3de080c #xa4c31a17 #xa9c8141e #x8af93e21 #x87f23028 #x90ef2233 #x9de42c3a
#x063d96dd #x0b3698d4 #x1c2b8acf #x112084c6 #x3211aef9 #x3f1aa0f0 #x2807b2eb #x250cbce2
#x6e65e695 #x636ee89c #x7473fa87 #x7978f48e #x5a49deb1 #x5742d0b8 #x405fc2a3 #x4d54ccaa
#xdaf741ec #xd7fc4fe5 #xc0e15dfe #xcdea53f7 #xeedb79c8 #xe3d077c1 #xf4cd65da #xf9c66bd3
#xb2af31a4 #xbfa43fad #xa8b92db6 #xa5b223bf #x86830980 #x8b880789 #x9c951592 #x919e1b9b
#x0a47a17c #x074caf75 #x1051bd6e #x1d5ab367 #x3e6b9958 #x33609751 #x247d854a #x29768b43
#x621fd134 #x6f14df3d #x7809cd26 #x7502c32f #x5633e910 #x5b38e719 #x4c25f502 #x412efb0b
#x618c9ad7 #x6c8794de #x7b9a86c5 #x769188cc #x55a0a2f3 #x58abacfa #x4fb6bee1 #x42bdb0e8
#x09d4ea9f #x04dfe496 #x13c2f68d #x1ec9f884 #x3df8d2bb #x30f3dcb2 #x27eecea9 #x2ae5c0a0
#xb13c7a47 #xbc37744e #xab2a6655 #xa621685c #x85104263 #x881b4c6a #x9f065e71 #x920d5078
#xd9640a0f #xd46f0406 #xc372161d #xce791814 #xed48322b #xe0433c22 #xf75e2e39 #xfa552030
#xb701ec9a #xba0ae293 #xad17f088 #xa01cfe81 #x832dd4be #x8e26dab7 #x993bc8ac #x9430c6a5
#xdf599cd2 #xd25292db #xc54f80c0 #xc8448ec9 #xeb75a4f6 #xe67eaaff #xf163b8e4 #xfc68b6ed
#x67b10c0a #x6aba0203 #x7da71018 #x70ac1e11 #x539d342e #x5e963a27 #x498b283c #x44802635
#x0fe97c42 #x02e2724b #x15ff6050 #x18f46e59 #x3bc54466 #x36ce4a6f #x21d35874 #x2cd8567d
#x0c7a37a1 #x017139a8 #x166c2bb3 #x1b6725ba #x38560f85 #x355d018c #x22401397 #x2f4b1d9e
#x642247e9 #x692949e0 #x7e345bfb #x733f55f2 #x500e7fcd #x5d0571c4 #x4a1863df #x47136dd6
#xdccad731 #xd1c1d938 #xc6dccb23 #xcbd7c52a #xe8e6ef15 #xe5ede11c #xf2f0f307 #xfffbfd0e
#xb492a779 #xb999a970 #xae84bb6b #xa38fb562 #x80be9f5d #x8db59154 #x9aa8834f #x97a38d46
))

(define Tks3 '#(
#x00000000 #x090d0b0e #x121a161c #x1b171d12 #x24342c38 #x2d392736 #x362e3a24 #x3f23312a
#x48685870 #x4165537e #x5a724e6c #x537f4562 #x6c5c7448 #x65517f46 #x7e466254 #x774b695a
#x90d0b0e0 #x99ddbbee #x82caa6fc #x8bc7adf2 #xb4e49cd8 #xbde997d6 #xa6fe8ac4 #xaff381ca
#xd8b8e890 #xd1b5e39e #xcaa2fe8c #xc3aff582 #xfc8cc4a8 #xf581cfa6 #xee96d2b4 #xe79bd9ba
#x3bbb7bdb #x32b670d5 #x29a16dc7 #x20ac66c9 #x1f8f57e3 #x16825ced #x0d9541ff #x04984af1
#x73d323ab #x7ade28a5 #x61c935b7 #x68c43eb9 #x57e70f93 #x5eea049d #x45fd198f #x4cf01281
#xab6bcb3b #xa266c035 #xb971dd27 #xb07cd629 #x8f5fe703 #x8652ec0d #x9d45f11f #x9448fa11
#xe303934b #xea0e9845 #xf1198557 #xf8148e59 #xc737bf73 #xce3ab47d #xd52da96f #xdc20a261
#x766df6ad #x7f60fda3 #x6477e0b1 #x6d7aebbf #x5259da95 #x5b54d19b #x4043cc89 #x494ec787
#x3e05aedd #x3708a5d3 #x2c1fb8c1 #x2512b3cf #x1a3182e5 #x133c89eb #x082b94f9 #x01269ff7
#xe6bd464d #xefb04d43 #xf4a75051 #xfdaa5b5f #xc2896a75 #xcb84617b #xd0937c69 #xd99e7767
#xaed51e3d #xa7d81533 #xbccf0821 #xb5c2032f #x8ae13205 #x83ec390b #x98fb2419 #x91f62f17
#x4dd68d76 #x44db8678 #x5fcc9b6a #x56c19064 #x69e2a14e #x60efaa40 #x7bf8b752 #x72f5bc5c
#x05bed506 #x0cb3de08 #x17a4c31a #x1ea9c814 #x218af93e #x2887f230 #x3390ef22 #x3a9de42c
#xdd063d96 #xd40b3698 #xcf1c2b8a #xc6112084 #xf93211ae #xf03f1aa0 #xeb2807b2 #xe2250cbc
#x956e65e6 #x9c636ee8 #x877473fa #x8e7978f4 #xb15a49de #xb85742d0 #xa3405fc2 #xaa4d54cc
#xecdaf741 #xe5d7fc4f #xfec0e15d #xf7cdea53 #xc8eedb79 #xc1e3d077 #xdaf4cd65 #xd3f9c66b
#xa4b2af31 #xadbfa43f #xb6a8b92d #xbfa5b223 #x80868309 #x898b8807 #x929c9515 #x9b919e1b
#x7c0a47a1 #x75074caf #x6e1051bd #x671d5ab3 #x583e6b99 #x51336097 #x4a247d85 #x4329768b
#x34621fd1 #x3d6f14df #x267809cd #x2f7502c3 #x105633e9 #x195b38e7 #x024c25f5 #x0b412efb
#xd7618c9a #xde6c8794 #xc57b9a86 #xcc769188 #xf355a0a2 #xfa58abac #xe14fb6be #xe842bdb0
#x9f09d4ea #x9604dfe4 #x8d13c2f6 #x841ec9f8 #xbb3df8d2 #xb230f3dc #xa927eece #xa02ae5c0
#x47b13c7a #x4ebc3774 #x55ab2a66 #x5ca62168 #x63851042 #x6a881b4c #x719f065e #x78920d50
#x0fd9640a #x06d46f04 #x1dc37216 #x14ce7918 #x2bed4832 #x22e0433c #x39f75e2e #x30fa5520
#x9ab701ec #x93ba0ae2 #x88ad17f0 #x81a01cfe #xbe832dd4 #xb78e26da #xac993bc8 #xa59430c6
#xd2df599c #xdbd25292 #xc0c54f80 #xc9c8448e #xf6eb75a4 #xffe67eaa #xe4f163b8 #xedfc68b6
#x0a67b10c #x036aba02 #x187da710 #x1170ac1e #x2e539d34 #x275e963a #x3c498b28 #x35448026
#x420fe97c #x4b02e272 #x5015ff60 #x5918f46e #x663bc544 #x6f36ce4a #x7421d358 #x7d2cd856
#xa10c7a37 #xa8017139 #xb3166c2b #xba1b6725 #x8538560f #x8c355d01 #x97224013 #x9e2f4b1d
#xe9642247 #xe0692949 #xfb7e345b #xf2733f55 #xcd500e7f #xc45d0571 #xdf4a1863 #xd647136d
#x31dccad7 #x38d1c1d9 #x23c6dccb #x2acbd7c5 #x15e8e6ef #x1ce5ede1 #x07f2f0f3 #x0efffbfd
#x79b492a7 #x70b999a9 #x6bae84bb #x62a38fb5 #x5d80be9f #x548db591 #x4f9aa883 #x4697a38d
))

(define rcon '#(
    #x01000000 #x02000000 #x04000000 #x08000000
    #x10000000 #x20000000 #x40000000 #x80000000
    #x1B000000 #x36000000
))

(define (Te0 x) (vector-ref TE0 x))
(define (Te1 x) (vector-ref TE1 x))
(define (Te2 x) (vector-ref TE2 x))
(define (Te3 x) (vector-ref TE3 x))
(define (Td0 x) (vector-ref TD0 x))
(define (Td1 x) (vector-ref TD1 x))
(define (Td2 x) (vector-ref TD2 x))
(define (Td3 x) (vector-ref TD3 x))

)
