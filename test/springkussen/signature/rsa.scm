#!r6rs
(import (rnrs)
	(springkussen signature descriptor)
	(springkussen signature rsa)
	(springkussen cipher asymmetric)
	(srfi :64)
	(testing))

(test-begin "RSA signature")

(define modulus #xF0C42DB8486FEB9595D8C78F908D04A9B6C8C77A36105B1BF2755377A6893DC4383C54EC6B5262E5688E5F9D9DD16497D0E3EA833DEE2C8EBCD1438389FCCA8FEDE7A88A81257E8B2709C494D42F723DEC2E0B5C09731C550DCC9D7E752589891CBBC3021307DD918E100B34C014A559E0E182AFB21A72B307CC395DEC995747)

(define public-key
  (key-factory:generate-key *key-factory:rsa*
   (make-rsa-public-key-parameter modulus #x010001)))
(define private-key
  (key-factory:generate-key *key-factory:rsa*
   (make-rsa-private-key-parameter 
    modulus
    #x2489108B0B6AF86BED9E44C2336442D5E227DBA55EF8E26A7E437194119077F003BC9C027852BB3126C99C16D5F1057BC8361DCB26A5B2DB4229DB3DE5BD979B2E597D1916D7BBC92746FC07595C76B44B39A476A65C86F086DC9283CA6D1EEFC14915982F9C4CED5F62A9FF3BE24218A99357B5B65C3B10AEB367E911EB9E21)))

(define (test-rsa-signer key pub-key bv)
  (define (sign)
    (let ((state (signer-descriptor:init rsa-signer-descriptor key)))
      (signer-descriptor:process! rsa-signer-descriptor state bv)
      (signer-descriptor:sign rsa-signer-descriptor state)))
  (define (verify S)
    (let ((state (verifier-descriptor:init rsa-verifier-descriptor pub-key)))
      (verifier-descriptor:process! rsa-verifier-descriptor state bv)
      (verifier-descriptor:verify rsa-verifier-descriptor state S)))
  (test-assert (verify (sign))))

(test-rsa-signer private-key public-key #vu8())
(test-rsa-signer private-key public-key #vu8(1))
(test-rsa-signer private-key public-key #vu8(1 2 3 4 5 6 7 8 9 0))

(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
