#!r6rs
(import (rnrs)
        (springkussen cipher password)
	(springkussen digest))

;; Use PBES1 with AES (not defined in PKCS#5)
(let ((cipher (make-pbe-cipher *pbe:pbes1*
               (make-pbe-cipher-encryption-scheme-parameter *scheme:aes*)))
      (parameter (make-cipher-parameter
		  ;; To use AES on PBES1, digest size and key size matters
		  ;; more precisely, key size + block length <= digest size
		  ;; For SHA-256, the digest size = 32
		  ;; Block size of AES = 16, so key size must be 16
		  ;; If you want to use longer key, then specify *digest:sha384*
		  ;; or bigger ones
		  (make-pbe-cipher-key-size-parameter 16)
		  (make-pbe-kdf-digest-parameter *digest:sha256*)
                  (make-pbe-cipher-salt-parameter
                   ;; Salt, length is not defined, but longer is better
                   #vu8(1 2 3 4 5 6 7 8))))
      (key (make-pbe-key "password"))
      (message (string->utf8 "Hello Springkussen")))
  (symmetric-cipher:encrypt-bytevector cipher key parameter message)
  ;; -> #vu8(186 140 4 96 249 188 31 42 26 194 129 128 60 3 76 132 75 30 232 7 181 43 135 138 146 44 129 197 215 249 97 209)
  (utf8->string (symmetric-cipher:decrypt-bytevector cipher key parameter #vu8(186 140 4 96 249 188 31 42 26 194 129 128 60 3 76 132 75 30 232 7 181 43 135 138 146 44 129 197 215 249 97 209)))
  ;; -> Hello Springkussen
  )

  



