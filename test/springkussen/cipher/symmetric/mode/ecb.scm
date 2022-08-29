(import (rnrs)
	(springkussen conditions)
	(springkussen cipher symmetric scheme aes)
	(springkussen cipher symmetric scheme des)
	(springkussen cipher symmetric scheme rc2)
	(springkussen cipher symmetric scheme rc5)
	(springkussen cipher symmetric scheme descriptor)
	(springkussen cipher symmetric mode ecb)
	(springkussen cipher symmetric mode descriptor)
	(springkussen cipher symmetric mode parameter)
	(srfi :64)
	(testing))

(define (test-ecb scheme vec . maybe-param)
  (define param (and (not (null? maybe-param)) (car maybe-param)))
  (define block-size (symmetric-scheme-descriptor-block-size scheme))
  (let ((key (integer->bytevector (vector-ref vec 1) (vector-ref vec 0)))
	(pt (integer->bytevector (vector-ref vec 2) block-size))
	(ct (integer->bytevector (vector-ref vec 3) block-size)))
    (define skey
      (symmetric-mode-descriptor:start ecb-mode-descriptor scheme #f key param))
    (define (encrypt skey pt)
      (symmetric-mode-descriptor:encrypt ecb-mode-descriptor skey pt))
    (define (decrypt skey ct)
      (symmetric-mode-descriptor:decrypt ecb-mode-descriptor skey ct))

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

(define (test-ecb-start-error msg pred scheme key param)
  (test-error msg pred
   (symmetric-mode-descriptor:start ecb-mode-descriptor scheme #f key param)))

(test-begin "ECB mode")

(define (springkussen-assertion? c)
  (and (assertion-violation? c) (springkussen-condition? c)))
(test-ecb-start-error "Invalid key AES" springkussen-assertion?
		      aes-descriptor 
		      #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15) #f)
(test-ecb-start-error "Invalid key AES 128 (1)" springkussen-assertion?
		      aes-128-descriptor
		      (bytevector-append
		       #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)
		       #vu8(1 2 3 4 5 6 7 8 ))
		      #f)
(test-ecb-start-error "Invalid key AES 128 (2)" springkussen-assertion?
		      aes-128-descriptor
		      (bytevector-append
		       #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)
		       #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))
		      #f)

;; apparently, AES-128 round must be 0 or 10 
(test-ecb-start-error "Invalid round AES 128" springkussen-assertion?
		      aes-128-descriptor
		      #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)
		      (make-round-parameter 9))

(test-ecb-start-error "Invalid key AES 192 (1)" springkussen-assertion?
		      aes-192-descriptor
		      (bytevector-append
		       #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))
		      #f)
(test-ecb-start-error "Invalid key AES 128 (2)" springkussen-assertion?
		      aes-192-descriptor
		      (bytevector-append
		       #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)
		       #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))
		      #f)
;; apparently, AES-192 round must be 0 or 12
(test-ecb-start-error "Invalid round AES 192" springkussen-assertion?
		      aes-192-descriptor
		      (bytevector-append
		       #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)
		       #vu8(1 2 3 4 5 6 7 8))
		      (make-round-parameter 11))

(test-ecb-start-error "Invalid key AES 256 (1)" springkussen-assertion?
		      aes-256-descriptor
		      (bytevector-append
		       #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))
		      #f)
(test-ecb-start-error "Invalid key AES 256 (2)" springkussen-assertion?
		      aes-256-descriptor
		      (bytevector-append
		       #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)
		       #vu8(1 2 3 4 5 6 7 8))
		      #f)
;; apparently, AES-256 round must be 0 or 14
(test-ecb-start-error "Invalid round AES 256" springkussen-assertion?
		      aes-256-descriptor
		      (bytevector-append
		       #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)
		       #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))
		      (make-round-parameter 13))

(test-ecb-start-error "Invalid key DES" springkussen-assertion?
		      des-descriptor #vu8(1 2 3 4 5 6 7) #f)
;; Round must be 0 or 16
(test-ecb-start-error "Invalid round DES " springkussen-assertion?
		      des-descriptor
		      #vu8(1 2 3 4 5 6 7 8)
		      (make-round-parameter 9))

(test-ecb-start-error "Invalid key DES3 " springkussen-assertion?
		      desede-descriptor
		      #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)
		      #f)
(test-ecb-start-error "Invalid key DES3 " springkussen-assertion?
		      desede-descriptor
		      (bytevector-append
		       #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)
		       #vu8(1 2 3 4 5 6 7))
		      #f)
;; Round must be 0 or 16
(test-ecb-start-error "Invalid round DES3 " springkussen-assertion?
		      desede-descriptor
		      (bytevector-append
		       #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)
		       #vu8(1 2 3 4 5 6 7 8))
		      (make-round-parameter 9))


(define test-aes-vectors
  '(
    ;; ken-len key plain cipher
    #(16 #x2b7e151628aed2a6abf7158809cf4f3c #x6bc1bee22e409f96e93d7e117393172a #x3ad77bb40d7a3660a89ecaf32466ef97)
    #(16 #x2b7e151628aed2a6abf7158809cf4f3c #xae2d8a571e03ac9c9eb76fac45af8e51 #xf5d3d58503b9699de785895a96fdbaaf)
    #(16 #x2b7e151628aed2a6abf7158809cf4f3c #x30c81c46a35ce411e5fbc1191a0a52ef #x43b1cd7f598ece23881b00e3ed030688)
    #(16 #x2b7e151628aed2a6abf7158809cf4f3c #xf69f2445df4f9b17ad2b417be66c3710 #x7b0c785e27e8ad3f8223207104725dd4)
    #(24 #x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b #x6bc1bee22e409f96e93d7e117393172a #xbd334f1d6e45f25ff712a214571fa5cc)
    #(24 #x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b #xae2d8a571e03ac9c9eb76fac45af8e51 #x974104846d0ad3ad7734ecb3ecee4eef)
    #(24 #x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b #x30c81c46a35ce411e5fbc1191a0a52ef #xef7afd2270e2e60adce0ba2face6444e)
    #(24 #x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b #xf69f2445df4f9b17ad2b417be66c3710 #x9a4b41ba738d6c72fb16691603c18e0e)
    #(32 #x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 #x6bc1bee22e409f96e93d7e117393172a #xf3eed1bdb5d2a03c064b5a7e3db181f8)
    #(32 #x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 #xae2d8a571e03ac9c9eb76fac45af8e51 #x591ccb10d410ed26dc5ba74a31362870)
    #(32 #x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 #x30c81c46a35ce411e5fbc1191a0a52ef #xb6ed21b99ca6f4f9f153e7b1beafed1d)
    #(32 #x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 #xf69f2445df4f9b17ad2b417be66c3710 #x23304b7a39f9f3ff067d8d8f9e24ecc7)
    ))

(for-each (lambda (v) (test-ecb aes-descriptor v)) test-aes-vectors)

(define test-des-vectors
  '(#(8 #x0000000000000000 #x0000000000000000 #x8CA64DE9C1B123A7)
    #(8 #xFFFFFFFFFFFFFFFF #xFFFFFFFFFFFFFFFF #x7359B2163E4EDC58)
    #(8 #x3000000000000000 #x1000000000000001 #x958E6E627A05557B)
    #(8 #x1111111111111111 #x1111111111111111 #xF40379AB9E0EC533)
    #(8 #x0123456789ABCDEF #x1111111111111111 #x17668DFC7292532D)
    #(8 #x1111111111111111 #x0123456789ABCDEF #x8A5AE1F81AB8F2DD)
    #(8 #x0000000000000000 #x0000000000000000 #x8CA64DE9C1B123A7)
    #(8 #xFEDCBA9876543210 #x0123456789ABCDEF #xED39D950FA74BCC4)
    #(8 #x7CA110454A1A6E57 #x01A1D6D039776742 #x690F5B0D9A26939B)
    #(8 #x0131D9619DC1376E #x5CD54CA83DEF57DA #x7A389D10354BD271)
    #(8 #x07A1133E4A0B2686 #x0248D43806F67172 #x868EBB51CAB4599A)
    #(8 #x3849674C2602319E #x51454B582DDF440A #x7178876E01F19B2A)
    #(8 #x04B915BA43FEB5B6 #x42FD443059577FA2 #xAF37FB421F8C4095)
    #(8 #x0113B970FD34F2CE #x059B5E0851CF143A #x86A560F10EC6D85B)
    #(8 #x0170F175468FB5E6 #x0756D8E0774761D2 #x0CD3DA020021DC09)
    #(8 #x43297FAD38E373FE #x762514B829BF486A #xEA676B2CB7DB2B7A)
    #(8 #x07A7137045DA2A16 #x3BDD119049372802 #xDFD64A815CAF1A0F)
    #(8 #x04689104C2FD3B2F #x26955F6835AF609A #x5C513C9C4886C088)
    #(8 #x37D06BB516CB7546 #x164D5E404F275232 #x0A2AEEAE3FF4AB77)
    #(8 #x1F08260D1AC2465E #x6B056E18759F5CCA #xEF1BF03E5DFA575A)
    #(8 #x584023641ABA6176 #x004BD6EF09176062 #x88BF0DB6D70DEE56)
    #(8 #x025816164629B007 #x480D39006EE762F2 #xA1F9915541020B56)
    #(8 #x49793EBC79B3258F #x437540C8698F3CFA #x6FBF1CAFCFFD0556)
    #(8 #x4FB05E1515AB73A7 #x072D43A077075292 #x2F22E49BAB7CA1AC)
    #(8 #x49E95D6D4CA229BF #x02FE55778117F12A #x5A6B612CC26CCE4A)
    #(8 #x018310DC409B26D6 #x1D9D5C5018F728C2 #x5F4C038ED12B2E41)
    #(8 #x1C587F1C13924FEF #x305532286D6F295A #x63FAC0D034D9F793)
    #(8 #x0101010101010101 #x0123456789ABCDEF #x617B3A0CE8F07100)
    #(8 #x1F1F1F1F0E0E0E0E #x0123456789ABCDEF #xDB958605F8C8C606)
    #(8 #xE0FEE0FEF1FEF1FE #x0123456789ABCDEF #xEDBFD1C66C29CCC7)
    #(8 #x0000000000000000 #xFFFFFFFFFFFFFFFF #x355550B2150E2451)
    #(8 #xFFFFFFFFFFFFFFFF #x0000000000000000 #xCAAAAF4DEAF1DBAE)
    #(8 #x0123456789ABCDEF #x0000000000000000 #xD5D44FF720683D0D)
    #(8 #xFEDCBA9876543210 #xFFFFFFFFFFFFFFFF #x2A2BB008DF97C2F2)
    #(8 #x7CA110454A1A6E57 #x01A1D6D039776742 #x690F5B0D9A26939B)
    #(8 #x0131D9619DC1376E #x5CD54CA83DEF57DA #x7A389D10354BD271)
    #(8 #x07A1133E4A0B2686 #x0248D43806F67172 #x868EBB51CAB4599A)
    #(8 #x3849674C2602319E #x51454B582DDF440A #x7178876E01F19B2A)
    #(8 #x04B915BA43FEB5B6 #x42FD443059577FA2 #xAF37FB421F8C4095)
    #(8 #x0113B970FD34F2CE #x059B5E0851CF143A #x86A560F10EC6D85B)
    #(8 #x0170F175468FB5E6 #x0756D8E0774761D2 #x0CD3DA020021DC09)
    #(8 #x43297FAD38E373FE #x762514B829BF486A #xEA676B2CB7DB2B7A)
    #(8 #x07A7137045DA2A16 #x3BDD119049372802 #xDFD64A815CAF1A0F)
    #(8 #x04689104C2FD3B2F #x26955F6835AF609A #x5C513C9C4886C088)
    #(8 #x37D06BB516CB7546 #x164D5E404F275232 #x0A2AEEAE3FF4AB77)
    #(8 #x1F08260D1AC2465E #x6B056E18759F5CCA #xEF1BF03E5DFA575A)
    #(8 #x584023641ABA6176 #x004BD6EF09176062 #x88BF0DB6D70DEE56)
    #(8 #x025816164629B007 #x480D39006EE762F2 #xA1F9915541020B56)
    #(8 #x49793EBC79B3258F #x437540C8698F3CFA #x6FBF1CAFCFFD0556)
    #(8 #x4FB05E1515AB73A7 #x072D43A077075292 #x2F22E49BAB7CA1AC)
    #(8 #x49E95D6D4CA229BF #x02FE55778117F12A #x5A6B612CC26CCE4A)
    #(8 #x018310DC409B26D6 #x1D9D5C5018F728C2 #x5F4C038ED12B2E41)
    #(8 #x1C587F1C13924FEF #x305532286D6F295A #x63FAC0D034D9F793)))

(define (->des2-key v)
  `#(,(* (vector-ref v 0) 2)
     ,(let ((bv (integer->bytevector (vector-ref v 1) 8)))
	(bytevector->integer (bytevector-append bv bv)))
     ,(vector-ref v 2)
     ,(vector-ref v 3)))
(define (->des3-key v)
  `#(,(* (vector-ref v 0) 3)
     ,(let ((bv (integer->bytevector (vector-ref v 1) 8)))
	(bytevector->integer (bytevector-append bv bv bv)))
     ,(vector-ref v 2)
     ,(vector-ref v 3)))

(for-each (lambda (v) (test-ecb des-descriptor v)) test-des-vectors)
(for-each (lambda (v) (test-ecb desede-descriptor v))
	  (map ->des2-key test-des-vectors))
(for-each (lambda (v) (test-ecb desede-descriptor v))
	  (map ->des3-key test-des-vectors))

;; RC5
;; We only support RC5-32/r/b, blocksize = 8
(define test-rc5-vectors
  '(
    #(16 #x915f4619be41b2516355a50110a9ce91 #x21a5dbee154b8f6d #xf7c013ac5b2b8952)
    #(16 #x783348e75aeb0f2fd7b169bb8dc16787 #xF7C013AC5B2B8952 #x2F42B3B70369FC92)
    #(16 #xDC49db1375a5584f6485b413b5f12baf #x2F42B3B70369FC92 #x65c178b284d197cc)
    ))
(for-each (lambda (v) (test-ecb rc5-descriptor v)) test-rc5-vectors)
;; From 
;; https://tools.ietf.org/id/draft-krovetz-rc6-rc5-vectors-00.html
(test-ecb rc5-descriptor
	  '#(16 #x000102030405060708090A0B0C0D0E0F #x0001020304050607 #x2A0EDC0E9431FF73)
	  (make-round-parameter 20))


;; RC2
(define test-rc2-vectors
  '(
    #(8  #x3000000000000000 #x1000000000000001 #x30649edf9be7d2c2)
    #(16 #x88bca90e90875a7f0f79c384627bafb2 #x0000000000000000 #x2269552ab0f85ca6)
    #(5 #x261E578EC9 #x1122334455667788 #x8270BE73E36295E0)
    ))

(for-each (lambda (v) (test-ecb rc2-descriptor v)) test-rc2-vectors)

(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
