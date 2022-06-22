(import (rnrs)
	(springkussen cipher symmetric scheme aes)
	(springkussen cipher symmetric mode ecb)
	(springkussen cipher symmetric mode descriptor)
	(srfi :64)
	(testing))

(define (test-ecb scheme vec)
  (let ((key (integer->bytevector (vector-ref vec 1) (vector-ref vec 0)))
	(pt (integer->bytevector (vector-ref vec 2) 16))
	(ct (integer->bytevector (vector-ref vec 3) 16)))
    (define skey
      (symmetric-mode-descriptor:start ecb-mode-descriptor scheme key #f))
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

(test-begin "ECB mode")

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

(test-end)

;; TODO schemes
