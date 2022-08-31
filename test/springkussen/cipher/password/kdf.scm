#!r6rs
(import (rnrs)
	(springkussen cipher password kdf)
	(springkussen digest)
	(springkussen mac)
	(srfi :64)
	(testing))

(test-begin "PBE KDF")

(test-assert (pbe-kdf-parameter? (make-pbe-kdf-digest-parameter *digest:sha1*)))
(test-assert (pbe-kdf-digest-parameter?
	      (make-pbe-kdf-digest-parameter *digest:sha1*)))

(let ((pbkdf-1 (make-pbkdf-1 (make-pbe-kdf-digest-parameter *digest:sha256*))))
  (test-equal "PBKDF-1 with SHA-256"
   (hex-string->bytevector
    "E2AF0AABF7C9B53D815876AEEE578F56F43DB6EAB44DFD207E83566C99F58BDD")
   (pbkdf-1 (string->utf8 "password") (string->utf8 "salt")
	    1024 (digest-descriptor-digest-size *digest:sha256*))))

(test-assert (pbe-kdf-parameter? (make-pbe-kdf-prf-parameter #f)))
(test-assert (pbe-kdf-prf-parameter? (make-pbe-kdf-prf-parameter #f)))


;; Test vector from https://www.ietf.org/rfc/rfc6070.txt
;; All SHA1
(define (test-pbkdf-2 md password salt c expected)
  (define param (make-pbe-kdf-prf-parameter
		 (mac->pbkdf2-prf *mac:hmac*
		 (make-partial-hmac-parameter md))))
  (let ((pbkdf-2 (make-pbkdf-2 param))
	(dk (hex-string->bytevector expected)))
    (test-equal dk (pbkdf-2 (string->utf8 password)
			    (string->utf8 salt)
			    c
			    (bytevector-length dk)))))

(test-pbkdf-2 *digest:sha1* "password" "salt" 1
	      "0c60c80f961f0e71f3a9b524af6012062fe037a6")
(test-pbkdf-2 *digest:sha1* "password" "salt" 2
	      "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")

(test-pbkdf-2 *digest:sha1* "password" "salt" 4096
	      "4b007901b765489abead49d926f721d065a429c1")

;; This doesn't return in a practical time...
#;(test-pbkdf-2 *digest:sha1* "password" "salt" 16777216
	      "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984")

(test-pbkdf-2 *digest:sha1*
	      "passwordPASSWORDpassword"
	      "saltSALTsaltSALTsaltSALTsaltSALTsalt"
	      4096
	      "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038")

(test-pbkdf-2 *digest:sha1* "pass\x0;word" "sa\x0;lt" 4096
	      "56fa6aa75548099dcc37d7f03425e0c3")


(test-end)
(exit (test-runner-fail-count (test-runner-current)))

	
