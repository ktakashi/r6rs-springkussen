#!r6rs
(import (rnrs)
	(springkussen mac)
	(springkussen digest)
	(srfi :64)
	(testing))

(test-begin "HMAC")

;; Test vector from RFC 4231
(define (test-hmac key data . digest&mac)
  (define (test-it digest&mac)
    (let ((digest (car digest&mac))
	  (expected (cdr digest&mac)))
      (let ((mac (make-mac *mac:hmac*
			   (make-mac-parameter
			    (make-digest-mac-parameter digest)
			    (make-key-mac-parameter key)))))
	(test-equal expected (mac:generate-mac mac data
					       (bytevector-length expected)))
	(let ((out (make-bytevector (bytevector-length expected))))
	  (test-equal expected (mac:generate-mac! mac data out))))))
  
  (for-each test-it digest&mac))

(test-hmac (hex-string->bytevector "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	   (hex-string->bytevector "4869205468657265")
	   (cons *digest:sha224* (hex-string->bytevector "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"))
	   (cons *digest:sha256* (hex-string->bytevector "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"))
	   (cons *digest:sha384* (hex-string->bytevector "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"))
	   (cons *digest:sha512* (hex-string->bytevector "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")))

(test-hmac (hex-string->bytevector "4a656665")
	   (hex-string->bytevector "7768617420646f2079612077616e7420666f72206e6f7468696e673f")
	   (cons *digest:sha224* (hex-string->bytevector "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44"))
	   (cons *digest:sha256* (hex-string->bytevector "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"))
	   (cons *digest:sha384* (hex-string->bytevector "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"))
	   (cons *digest:sha512* (hex-string->bytevector "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")))

(test-hmac (hex-string->bytevector "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	   (hex-string->bytevector "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	   (cons *digest:sha224* (hex-string->bytevector "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea"))
	   (cons *digest:sha256* (hex-string->bytevector "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"))
	   (cons *digest:sha384* (hex-string->bytevector "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27"))
	   (cons *digest:sha512* (hex-string->bytevector "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb")))

(test-hmac (hex-string->bytevector "0102030405060708090a0b0c0d0e0f10111213141516171819")
	   (hex-string->bytevector "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
	   (cons *digest:sha224* (hex-string->bytevector "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a"))
	   (cons *digest:sha256* (hex-string->bytevector "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"))
	   (cons *digest:sha384* (hex-string->bytevector "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb"))
	   (cons *digest:sha512* (hex-string->bytevector "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd")))

(test-hmac (hex-string->bytevector "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
	   (hex-string->bytevector "546573742057697468205472756e636174696f6e")
	   (cons *digest:sha224* (hex-string->bytevector "0e2aea68a90c8d37c988bcdb9fca6fa8"))
	   (cons *digest:sha256* (hex-string->bytevector "a3b6167473100ee06e0c796c2955552b"))
	   (cons *digest:sha384* (hex-string->bytevector "3abf34c3503b2a23a46efc619baef897"))
	   (cons *digest:sha512* (hex-string->bytevector "415fad6271580a531d4179bc891d87a6")))

(test-hmac (hex-string->bytevector "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	   (hex-string->bytevector "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374")
	   (cons *digest:sha224* (hex-string->bytevector "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e"))
	   (cons *digest:sha256* (hex-string->bytevector "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"))
	   (cons *digest:sha384* (hex-string->bytevector "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"))
	   (cons *digest:sha512* (hex-string->bytevector "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598")))

(test-hmac (hex-string->bytevector "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	   (hex-string->bytevector "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e")
	   (cons *digest:sha224* (hex-string->bytevector "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1"))
	   (cons *digest:sha256* (hex-string->bytevector "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"))
	   (cons *digest:sha384* (hex-string->bytevector "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e"))
	   (cons *digest:sha512* (hex-string->bytevector "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58")))

(test-end)
