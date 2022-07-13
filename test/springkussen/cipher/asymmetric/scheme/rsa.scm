#!r6rs
(import (rnrs)
	(springkussen asn1)
	(springkussen cipher asymmetric scheme descriptor)
	(springkussen cipher asymmetric scheme rsa)
	(springkussen cipher asymmetric key)
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

(let ((expected (asn1-object->bytevector
		 (der-sequence
		  (der-sequence
		   (make-der-object-identifier "1.2.840.113549.1.1.1"))
		  (make-der-bit-string
		   (asn1-object->bytevector
		    (der-sequence
		     (make-der-integer modulus)
		     (make-der-integer #x010001))))))))
  (test-equal "RSA public key export" expected
	      (asymmetric-key:export-key *rsa-public-key-operation* public-key))
  (test-assert "RSA public key import (1)"
	       (rsa-public-key?
		(asymmetric-key:import-key *rsa-public-key-operation* expected)))
  (let ((key (asymmetric-key:import-key *rsa-public-key-operation* expected)))
    (test-equal #x010001 (rsa-public-key-exponent key))
    (test-equal modulus (rsa-public-key-modulus key))))


(let ((modulus #xbcea0cd9c6fafc81ce82d821c29afa58c19d67359e224c0a7ee8b4d7c171e1e715ca30a441dea0b4290ce6410326044d968a2895734be500f82f8dac46e6dc767b83011eac45db0fbde85ebc84e812f82aee530726db8fd8c3b05d7137a990f04912515d5a70ff442e6a8fe2e83dd5687407a5cb7c4afcd197151b4a5a5c1c16c18786bde8b22bfaeb6ed246bd9ec10c90f2e8bf81c7b7e504fa1c4432e33d98036df9bc57cf826f0bc35e6476a6636628431fcaeae8bdc9df88d0fb386e1145cc25ab02f93c4b478a5363a8e3357701fafc4ae090217d00a5c8fe1bc91ef691c2c223d5ed8d42435ba3191fb43e23aa75138b082ed63c2973e21c56db3c4199)
      (public-exponent #x10001)
      (private-exponent #x7ef6598e9f311d34ec2279b92ebdd3548543111332e4dff009dcc1756377f317c8482baaa8ee4358f161cef99071236135b442943679a23da58ee80b0957ac81207f29e880652e55850f3f64397a730d40650d7df7fa85d16bab0311cd13f3e9d9622b36af4ad3f3f1b20263c02b965a6de899df88f828b37f735af4fc877d041248277afc1e68f3070c4e2a8e6b671eb5ce65e622f221bb7fe6422466507c956c2a724d212abfabc4e4d835a3899e97770f62617864f2dece3fd43601c9b90081906e24a4ad89d02042cc64e9a9b290d670dc55fb421580df12c2fcf8ec86bf39c83368eff8ae707df246e31580496d7d0da12ab1c6dda134749fbc0a5886d1)
      (p #xe5db4e7e421e4a5018edd19121cb358fee2df4c965890f40e3059778c743b5b91d394e9c3d1034fcb0f8e85963ca1456625774e7d4a71b8f1435ee9bbe645178ca49613eed9dc63b86212046526b992df617b1851570598f57d9d6ebea2158b02afea01d824248e64f784772c4b499c807b9cde92d721015b2017485d6061945)
      (q #xd266a1953ff5d72f6db1cd130502b9b8f91c089bf0afb0f2efe5504ceb930d6e3dfa22f2784a46293450ebba0486aea4b3bda34a933c0777f920569fdd5bf2757d36c7d3b5dd49fda173e2a8d158ea7d6da9095ab0efeaf5a3d164e12f7cbe6fdf924a21c67bb80b6699e8c86b64d5b1de71c26b849f5f8e45e2d6ff11fbca45)
      (dP #xdcad98c68f2415a4a0ca72912c28b4dbe2882ca3cedfafcd5428622c8ae2eeed32a97a577628c1367991ff411315484147593fdbf3c61c2759f80d85695d56fae8fb5a69d827c9d20c0c71b812194b8f5cdd92897af3ca885c87c057ef08e4e4fde248470c70271d36defb79ac70d7d3bbd71f61e747c3399114e49239d0d121)
      (dQ #x620f131fcc3f779ad3351aaed29702980301ddc14fdb924ca721e8daf0b0088268c03ba96606b7cc5c659a7787c47d80a584aca60518e5223529ad35b4a535cb2c206be16fd142bac2948ffebe1302b6927545b6cee002519997edbc45b58dcbf616e815f5bb937b3cc65e878a05e4d29129d3c2e87c9ebc6035e89dd873d141)
      (qP #x399cc2dc8e118d80f6ac1225c7ee6414271302b2f4b62d4279c37fcb91cf490ec9842795ebdf6b761938c7fd378bef9210c1673e1d6f7c64f10a6f569fccc6d2d280c4796fe7daf4dc3da74bedea5bdec53f011902c8febea43e3be675b4a465ec846c8f6dceea72da3719ca2a02c5ff389a252739664cd778e776763bc681c))
  (let ((key (rsa-crt-private-key-builder
	      (modulus modulus)
	      (public-exponent public-exponent)
	      (private-exponent private-exponent)
	      (p p)
	      (q q)
	      (dP dP)
	      (dQ dQ)
	      (qP qP)))
	(expected (asn1-object->bytevector
		   (der-sequence
		    (make-der-integer 0)
		    (make-der-integer modulus)
		    (make-der-integer public-exponent)
		    (make-der-integer private-exponent)
		    (make-der-integer p)
		    (make-der-integer q)
		    (make-der-integer dP)
		    (make-der-integer dQ)
		    (make-der-integer qP)))))
    (test-equal "RSA private key export" expected
		(asymmetric-key:export-key *rsa-private-key-operation* key))
    (test-assert "RSA private key import (1)"
		 (rsa-crt-private-key?
		  (asymmetric-key:import-key *rsa-private-key-operation*
					     expected)))
    (let ((key (asymmetric-key:import-key *rsa-private-key-operation* expected)))
      (test-equal #x010001 (rsa-crt-private-key-public-exponent key))
      (test-equal modulus (rsa-private-key-modulus key)))))

(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
