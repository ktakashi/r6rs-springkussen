#!r6rs
(import (rnrs)
        (springkussen cipher password))

;; Use PBES1 with DES
(let ((cipher (make-pbe-cipher *pbe:pbes1*
               (make-pbe-cipher-encryption-scheme-parameter *scheme:des*)))
      (parameter (make-cipher-parameter
                  (make-pbe-cipher-salt-parameter
                   ;; Salt, length is not defined, but longer is better
                   #vu8(1 2 3 4 5 6 7 8))))
      (key (make-pbe-key "password"))
      (message (string->utf8 "Hello Springkussen")))
  (symmetric-cipher:encrypt-bytevector cipher key parameter message)
  ;; -> #vu8(186 140 4 96 249 188 31 42 26 194 129 128 60 3 76 132 75 30 232 7 181 43 135 138 146 44 129 197 215 249 97 209)
  (utf8->string (symmetric-cipher:decrypt-bytevector cipher key parameter #vu8(227 230 106 9 106 74 212 199 228 241 133 149 112 36 229 172 31 39 125 187 85 179 67 188)))
  ;; -> Hello Springkussen
  )

  



