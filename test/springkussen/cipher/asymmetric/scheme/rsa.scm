#!r6rs
(import (rnrs)
	(springkussen cipher asymmetric scheme descriptor)
	(springkussen cipher asymmetric scheme rsa)
	(srfi :64)
	(testing))


(test-begin "RSA encryption")

;; Test vector from http://cryptomanager.com/tv.html
(define modulus #xF0C42DB8486FEB9595D8C78F908D04A9B6C8C77A36105B1BF2755377A6893DC4383C54EC6B5262E5688E5F9D9DD16497D0E3EA833DEE2C8EBCD1438389FCCA8FEDE7A88A81257E8B2709C494D42F723DEC2E0B5C09731C550DCC9D7E752589891CBBC3021307DD918E100B34C014A559E0E182AFB21A72B307CC395DEC995747)

(define public-key
  (rsa-public-key-builder
   (modulus modulus)
   (exponent #x010001)))
(define private-key
  (rsa-private-key-builder
   (modulus modulus)
   (private-exponent #x2489108B0B6AF86BED9E44C2336442D5E227DBA55EF8E26A7E437194119077F003BC9C027852BB3126C99C16D5F1057BC8361DCB26A5B2DB4229DB3DE5BD979B2E597D1916D7BBC92746FC07595C76B44B39A476A65C86F086DC9283CA6D1EEFC14915982F9C4CED5F62A9FF3BE24218A99357B5B65C3B10AEB367E911EB9E21)))

(let ((in (integer->bytevector #x11223344 4))
      (result (integer->bytevector #x505B09BD5D0E66D7C8829F5B473ED34DB5CFDBB5D58CE78329C8BF8520E486D3C4CF9B70C6346594358080F43F47EE863CFAF2A2E5F03D1E13D6FEC57DFB1D552224C461DA411CFE5D0B05BA877E3A42F6DE4DA46A965C9B695EE2D50E400894061CB0A21CA3A524B407E9FFBA87FC966B3BA94590849AEB908AAFF4C719C2E4 128))
      (rsa rsa-descriptor))
  (define (encrypt bv)
    (let* ((state-key (asymmetric-scheme-descriptor:start rsa public-key #f))
	   (r (asymmetric-scheme-descriptor:encrypt rsa state-key bv)))
      (asymmetric-scheme-descriptor:done rsa state-key)
      r))
  (define (decrypt bv)
    (let* ((state-key (asymmetric-scheme-descriptor:start rsa private-key #f))
	   (r (asymmetric-scheme-descriptor:decrypt rsa state-key bv)))
      (asymmetric-scheme-descriptor:done rsa state-key)
      r))
  (test-equal result (encrypt in))
  (test-equal (bytevector->integer in)
	      (bytevector->integer (decrypt result))))

(test-end)
