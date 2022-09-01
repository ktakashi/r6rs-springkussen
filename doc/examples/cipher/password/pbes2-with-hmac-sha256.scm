#!r6rs
(import (rnrs)
        (springkussen cipher password)
	(springkussen digest)
	(springkussen mac))

;; Use PBES2 with AES
(let ((cipher (make-pbe-cipher *pbe:pbes2*
               (make-pbe-cipher-encryption-scheme-parameter *scheme:aes*)))
      (parameter (make-cipher-parameter
		  ;; Specifying PRF of HMAC-SHA256
		  (make-pbe-kdf-prf-parameter
		   (mac->pbkdf2-prf *mac:hmac*
		    (make-partial-hmac-parameter *digest:sha256*)))
                  (make-iv-paramater
                   ;; Initial vector of AES block size
                   #vu8(1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6))
                  (make-pbe-cipher-salt-parameter
                   ;; Salt, length is not defined, but longer is better
                   #vu8(1 2 3 4 5 6 7 8))))
      (key (make-pbe-key "password"))
      (message (string->utf8 "Hello Springkussen")))
  (symmetric-cipher:encrypt-bytevector cipher key parameter message)
  ;; -> #vu8(179 174 255 106 189 59 66 198 250 7 119 55 0 131 208 15 252 193 79 138 197 202 134 238 208 245 178 53 114 176 174 68)
  (utf8->string (symmetric-cipher:decrypt-bytevector cipher key parameter #vu8(179 174 255 106 189 59 66 198 250 7 119 55 0 131 208 15 252 193 79 138 197 202 134 238 208 245 178 53 114 176 174 68)))
  ;; -> Hello Springkussen
  )
