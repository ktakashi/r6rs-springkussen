(import (rnrs)
	(springkussen conditions)
	(springkussen cipher symmetric)
	(srfi :64)
	(testing))

(test-begin "Symmetric cipher APIs")

(define (test-encrypt/decrypt cipher-spec key pt . opt)
  ;; If the cipher is ECB, we don't have to
  ;; but if it's CBC, then we need to make 2 ciphers
  (define enc-cipher (apply make-symmetric-cipher cipher-spec key opt))
  (define dec-cipher (apply make-symmetric-cipher cipher-spec key opt))
  (let ((ct (symmetric-cipher:encrypt-bytevector enc-cipher pt)))
    (test-assert "Plain text != cipher text" (not (bytevector=? pt ct)))
    (test-equal "Decrypt"
		pt (symmetric-cipher:decrypt-bytevector dec-cipher ct))))

(test-assert (symmetric-cipher-spec?
	      (symmetric-cipher-spec-builder (scheme *scheme:aes*)
					     (mode *mode:ecb*))))
(test-error springkussen-condition?
	    (symmetric-cipher-spec-builder (mode *mode:ecb*)))
(test-error springkussen-condition?
	    (symmetric-cipher-spec-builder (scheme *scheme:aes*)))

(test-assert "Enc scheme" (symmetric-scheme-descriptor? *scheme:aes*))
(test-assert "Enc scheme" (symmetric-scheme-descriptor? *scheme:aes-128*))
(test-assert "Enc scheme" (symmetric-scheme-descriptor? *scheme:aes-192*))
(test-assert "Enc scheme" (symmetric-scheme-descriptor? *scheme:aes-256*))
(test-assert "Enc scheme" (symmetric-scheme-descriptor? *scheme:des*))
(test-assert "Enc scheme" (symmetric-scheme-descriptor? *scheme:desede*))
(test-assert "Enc scheme" (symmetric-scheme-descriptor? *scheme:rc2*))
(test-assert "Enc scheme" (symmetric-scheme-descriptor? *scheme:rc5*))

(test-assert "Enc mode" (symmetric-mode-descriptor? *mode:ecb*))
(test-assert "Enc mode" (symmetric-mode-descriptor? *mode:cbc*))

(test-assert "Mode parameter" (mode-parameter? (make-iv-paramater #vu8())))
(test-assert "Mode parameter"
	     (mode-parameter? (make-mode-parameter (make-iv-paramater #vu8()))))

(test-assert "Symmetric key" (symmetric-key? (make-symmetric-key #vu8())))

;; AES/ECB
(let ((aes-ecb-cipher-spec (symmetric-cipher-spec-builder
			    (scheme *scheme:aes*)
			    (mode *mode:ecb*))))
  (test-encrypt/decrypt aes-ecb-cipher-spec
			(make-symmetric-key
			 #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))
			;; non block size
			#vu8(1 2 3 4 5 6 7 8 9 10)))
;; AES/CBC
(let ((aes-ecb-cipher-spec (symmetric-cipher-spec-builder
			    (scheme *scheme:aes*)
			    (mode *mode:cbc*))))
  (test-encrypt/decrypt aes-ecb-cipher-spec
			(make-symmetric-key
			 #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))
			#vu8(1 2 3 4 5 6 7 8 9 10)
			(make-iv-paramater
			 #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))))

(test-end)
