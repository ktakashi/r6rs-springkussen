(import (rnrs)
	(springkussen conditions)
	(springkussen cipher symmetric scheme aes)
	(springkussen cipher symmetric scheme des)
	(springkussen cipher symmetric scheme rc5)
	(springkussen cipher symmetric scheme descriptor)
	(springkussen cipher symmetric mode cbc)
	(springkussen cipher symmetric mode descriptor)
	(springkussen cipher symmetric mode parameter)
	(srfi :64)
	(testing))

(define (construct-parameter scheme param)
  (define block-size (symmetric-scheme-descriptor-block-size scheme))
  (let loop ((p '()) (in param))
    (if (null? in)
	(apply make-composite-parameter p)
	(let ((p0 (car in)))
	  (loop (case (car p0)
		  ((round)
		   (cons (make-round-parameter (cadr p0)) p))
		  ((iv)
		   (cons (make-iv-paramater
			  (integer->bytevector (cadr p0) block-size))
			 p))
		  ;; ignore
		  (else p))
		(cdr in))))))

(define (test-cbc scheme vec)
  (define param (construct-parameter scheme (vector-ref vec 4)))
  (define block-size (symmetric-scheme-descriptor-block-size scheme))
  (let ((key (integer->bytevector (vector-ref vec 1) (vector-ref vec 0)))
	(pt (integer->bytevector (vector-ref vec 2) block-size))
	(ct (integer->bytevector (vector-ref vec 3) block-size)))
    (define skey
      (symmetric-mode-descriptor:start cbc-mode-descriptor scheme key param))
    (define (encrypt skey pt)
      (symmetric-mode-descriptor:set-iv! cbc-mode-descriptor skey
					 (parameter-iv param))
      (symmetric-mode-descriptor:encrypt cbc-mode-descriptor skey pt))
    (define (decrypt skey ct)
      (symmetric-mode-descriptor:set-iv! cbc-mode-descriptor skey
					 (parameter-iv param))
      (symmetric-mode-descriptor:decrypt cbc-mode-descriptor skey ct))

    (test-equal (string-append "encrypt: (" 
			       (number->string (vector-ref vec 0))
			       ") "
			       (number->string (vector-ref vec 2) 16)
			       " -> "
			       (number->string (vector-ref vec 3) 16))
		ct
		(encrypt skey pt))

    (test-equal (string-append "decrypt: (" 
			       (number->string (vector-ref vec 0))
			       ") "
			       (number->string (vector-ref vec 3) 16)
			       " -> "
			       (number->string (vector-ref vec 2) 16))
		pt
		(decrypt skey ct))))

(test-begin "CBC mode")

(define test-rc5-vector
  '(
    ;; keylen key plain cipher param
    ;; round = 8 is too small...
    #(08 #x0102030405060708                 #xffffffffffffffff #xe493f1c1bb4d6e8c ((round 12) (iv #x0000000000000000)))
;;    #(08 #x0102030405060708                 #x1020304050607080 #x5c4c041e0f217ac3 ((round  8) (iv #x0102030405060708)))
    #(08 #x0102030405060708                 #x1020304050607080 #x921f12485373b4f7 ((round 12) (iv #x0102030405060708)))
    #(08 #x0102030405060708                 #x1020304050607080 #x5ba0ca6bbe7f5fad ((round 16) (iv #x0102030405060708)))
;;    #(16 #x01020304050607081020304050607080 #x1020304050607080 #xc533771cd0110e63 ((round  8) (iv #x0102030405060708)))
    #(16 #x01020304050607081020304050607080 #x1020304050607080 #x294ddb46b3278d60 ((round 12) (iv #x0102030405060708)))
    #(16 #x01020304050607081020304050607080 #x1020304050607080 #xdad6bda9dfe8f7e8 ((round 16) (iv #x0102030405060708)))
    ))

(for-each (lambda (v) (test-cbc rc5-descriptor v)) test-rc5-vector)

(define test-aes-128-vector
  '(
    #(16 #x2b7e151628aed2a6abf7158809cf4f3c #x6bc1bee22e409f96e93d7e117393172a #x7649abac8119b246cee98e9b12e9197d ((iv #x000102030405060708090A0B0C0D0E0F)))
    #(16 #x2b7e151628aed2a6abf7158809cf4f3c #xae2d8a571e03ac9c9eb76fac45af8e51 #x5086cb9b507219ee95db113a917678b2 ((iv #x7649ABAC8119B246CEE98E9B12E9197D)))
    #(16 #x2b7e151628aed2a6abf7158809cf4f3c #x30c81c46a35ce411e5fbc1191a0a52ef #x73bed6b8e3c1743b7116e69e22229516 ((iv #x5086CB9B507219EE95DB113A917678B2)))
    #(16 #x2b7e151628aed2a6abf7158809cf4f3c #xf69f2445df4f9b17ad2b417be66c3710 #x3ff1caa1681fac09120eca307586e1a7 ((iv #x73BED6B8E3C1743B7116E69E22229516)))
    ))
(for-each (lambda (v) (test-cbc aes-128-descriptor v)) test-aes-128-vector)

(define test-aes-192-vector
  '(
    #(24 #x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b #x6bc1bee22e409f96e93d7e117393172a #x4f021db243bc633d7178183a9fa071e8 ((iv #x000102030405060708090A0B0C0D0E0F)))
    #(24 #x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b #xae2d8a571e03ac9c9eb76fac45af8e51 #xb4d9ada9ad7dedf4e5e738763f69145a ((iv #x4F021DB243BC633D7178183A9FA071E8)))
    #(24 #x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b #x30c81c46a35ce411e5fbc1191a0a52ef #x571b242012fb7ae07fa9baac3df102e0 ((iv #xB4D9ADA9AD7DEDF4E5E738763F69145A)))
    #(24 #x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b #xf69f2445df4f9b17ad2b417be66c3710 #x08b0e27988598881d920a9e64f5615cd ((iv #x571B242012FB7AE07FA9BAAC3DF102E0)))
    ))
(for-each (lambda (v) (test-cbc aes-192-descriptor v)) test-aes-192-vector)

(define test-aes-256-vector
  '(
    #(32 #x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 #x6bc1bee22e409f96e93d7e117393172a #xf58c4c04d6e5f1ba779eabfb5f7bfbd6 ((iv #x000102030405060708090A0B0C0D0E0F)))
    #(32 #x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 #xae2d8a571e03ac9c9eb76fac45af8e51 #x9cfc4e967edb808d679f777bc6702c7d ((iv #xF58C4C04D6E5F1BA779EABFB5F7BFBD6)))
    #(32 #x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 #x30c81c46a35ce411e5fbc1191a0a52ef #x39f23369a9d9bacfa530e26304231461 ((iv #x9CFC4E967EDB808D679F777BC6702C7D)))
    #(32 #x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 #xf69f2445df4f9b17ad2b417be66c3710 #xb2eb05e2c39be9fcda6c19078c6a9d1b ((iv #x39F23369A9D9BACFA530E26304231461)))
    ))
(for-each (lambda (v) (test-cbc aes-256-descriptor v)) test-aes-256-vector)


(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
