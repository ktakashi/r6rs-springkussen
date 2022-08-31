#!r6rs
(import (rnrs)
	(springkussen cipher asymmetric key)
	(springkussen signature ecdsa key)
	(only (springkussen math ec) make-ec-point)
	(srfi :64)
	(testing))

(test-begin "ECDSA key")

(define ecdsa-private-key-bv
  (hex-string->bytevector "307402010104204620065C9056C1FB4A91D41FBC78444ADC72486EEDAAF2FC98E13FBD8D935F44A00706052B8104000AA14403420004D4CB472319463F94C046A05C72B75D366D459D81F5169FA89C44F3E4A6D73D2786E451B028C51719F02649926ADA010D50B15EC30CA6B7EF5B4D7923059861F0"))

(define ecdsa-public-key-bv
  (hex-string->bytevector "3056301006072A8648CE3D020106052B8104000A03420004D4CB472319463F94C046A05C72B75D366D459D81F5169FA89C44F3E4A6D73D2786E451B028C51719F02649926ADA010D50B15EC30CA6B7EF5B4D7923059861F0"))

(test-assert (ecdsa-private-key?
	      (asymmetric-key:import-key *ecdsa-private-key-operation*
					 ecdsa-private-key-bv)))

(let ((key (asymmetric-key:import-key *ecdsa-private-key-operation*
				      ecdsa-private-key-bv)))
  (test-equal #x4620065c9056c1fb4a91d41fbc78444adc72486eedaaf2fc98e13fbd8d935f44
	      (ecdsa-private-key-d key))
  (test-equal secp256k1 (ecdsa-private-key-ec-parameter key))
  (test-equal ecdsa-private-key-bv
	      (asymmetric-key:export-key *ecdsa-private-key-operation* key)))

(test-assert (ecdsa-public-key?
	      (asymmetric-key:import-key *ecdsa-public-key-operation*
					 ecdsa-public-key-bv)))
(let ((key (asymmetric-key:import-key *ecdsa-public-key-operation*
				      ecdsa-public-key-bv)))
  (test-equal (make-ec-point #xd4cb472319463f94c046a05c72b75d366d459d81f5169fa89c44f3e4a6d73d27
			     #x86e451b028c51719f02649926ada010d50b15ec30ca6b7ef5b4d7923059861f0)
	      (ecdsa-public-key-Q key))
  (test-equal secp256k1 (ecdsa-public-key-ec-parameter key))
  (test-equal ecdsa-public-key-bv
	      (asymmetric-key:export-key *ecdsa-public-key-operation* key)))

(define-syntax test-ec-parameter?
  (syntax-rules ()
    ((_ name ...)
     (begin
       (test-assert 'name (ec-parameter? name))
       ...))))

(test-ec-parameter? NIST-P-192 secp192r1
		    NIST-P-224 secp224r1
		    NIST-P-256 secp256r1
		    NIST-P-384 secp384r1
		    NIST-P-521 secp521r1
		    
		    NIST-K-163 sect163k1
		    NIST-K-233 sect233k1
		    NIST-K-283 sect283k1
		    NIST-K-409 sect409k1
		    NIST-K-571 sect571k1
		    
		    NIST-B-163 sect163r2
		    NIST-B-233 sect233r1
		    NIST-B-283 sect283r1
		    NIST-B-409 sect409r1
		    NIST-B-571 sect571r1
		    
		    secp192k1
		    secp224k1
		    secp256k1
		    
		    sect163r1
		    sect239k1
		    sect113r1)

(let ((kp (key-pair-factory:generate-key-pair *ecdsa-key-pair-factory*
	    (make-ecdsa-ec-parameter NIST-P-256))))
  (test-assert (ecdsa-private-key? (key-pair-private kp)))
  (test-assert (ecdsa-public-key? (key-pair-public kp))))

(test-end)
(exit (test-runner-fail-count (test-runner-current)))
