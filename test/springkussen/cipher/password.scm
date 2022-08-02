#!r6rs
(import (rnrs)
	(springkussen cipher symmetric)
	(springkussen cipher password)
	(springkussen digest)
	(springkussen mac)
	(srfi :64)
	(testing))

(test-begin "PBE")

(test-assert (symmetric-cipher?
	      (make-pbe-cipher *pbe:pbes1*
	       (make-pbe-cipher-encryption-scheme-parameter *scheme:des*))))

(let ((cipher (make-pbe-cipher *pbe:pbes1*
	       (make-pbe-cipher-encryption-scheme-parameter *scheme:des*)))
      (key (make-pbe-key "password"))
      (salt (make-pbe-cipher-salt-parameter #vu8(1 2 3 4 5 6 7 8))))
  (test-assert (pbe-key? key))
  (test-equal #vu8()
	      (symmetric-cipher:decrypt-bytevector
	       cipher key
	       (make-cipher-parameter salt)
	       (symmetric-cipher:encrypt-bytevector
		cipher key
		(make-cipher-parameter salt)
		#vu8()))))

(test-end)
(exit (zero?(test-runner-fail-count (test-runner-current))))

	
