#!r6rs
(import (rnrs)
	(springkussen cipher asymmetric key)
	(springkussen signature descriptor)
	(springkussen signature parameters)
	(springkussen signature rsa)
	(springkussen cipher asymmetric)
	(springkussen digest)
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

(define (test-rsa-verifier key M S md verify)
  (let ((s (verifier-descriptor:init rsa-verifier-descriptor key
	    (make-signature-parameter
	     (make-signature-digest-parameter md)
	     (make-rsa-signature-verify-parameter verify)))))
    (verifier-descriptor:process! rsa-verifier-descriptor s M)
    (test-assert (verifier-descriptor:verify rsa-verifier-descriptor s S))))

(test-rsa-verifier public-key
		   #vu8(1)
		   (hex-string->bytevector "BAAB4843FB7B923928FCB414603F93919A14E959A496EBD500E4BA38A5C786F3232EED41B77CB6452CC464AC601CE25F03583BD6C6A331876966C2A9EF9F2E11AE2824C38D2DFA24BEADCD414E626AEE640A3E70E051A3C5859417CB333A15C96065944E73641E258A656CAA9D2026BF4EE088E489F85A0CB230A14FE945B1AA")
		   *digest:sha1*
		   pkcs1-emsa-v1.5-verify)
(test-rsa-verifier public-key
		   #vu8()
		   (hex-string->bytevector "33EED9F552004A6D83FC81BED4286C5DBACD7B0E6D8169BF67EBAE8A0D99AB60518632A04ACC73C090CE1EA965133FD65E8AFBC13155CC0E830836ECC7ECBE9AF3C2ACB94BA8F1D471938BB02AA0E575A8837835AD4B740782DBAC34F6DE96451FB19E22B4711D39F8D041DF883F9AB84324824E190E78675749CB0BDF6CBD45")
		   *digest:sha256*
		   pkcs1-emsa-v1.5-verify)

;; if verifier can verify the signature generated by the other library,
;; we can sort of trust our verifier. So signature can be verified like
;; this
(define (test-rsa-signer key pub-key bv)
  (define param
    (make-signature-parameter
     (make-signature-digest-parameter *digest:sha256*)
     (make-rsa-signature-encode-parameter pkcs1-emsa-v1.5-encode)
     (make-rsa-signature-verify-parameter pkcs1-emsa-v1.5-verify)))
  (define (sign)
    (let ((state (signer-descriptor:init rsa-signer-descriptor key param)))
      (signer-descriptor:process! rsa-signer-descriptor state bv)
      (signer-descriptor:sign rsa-signer-descriptor state)))
  (define (verify S)
    (let ((state (verifier-descriptor:init rsa-verifier-descriptor pub-key param)))
      (verifier-descriptor:process! rsa-verifier-descriptor state bv)
      (verifier-descriptor:verify rsa-verifier-descriptor state S)))
  (test-assert (verify (sign))))

(test-rsa-signer private-key public-key #vu8())
(test-rsa-signer private-key public-key #vu8(1))
(test-rsa-signer private-key public-key #vu8(1 2 3 4 5 6 7 8 9 0))

;;
(define (test-rsa-emsa-pss pub-key-asn msg sig param)
  (define pub-key
    (asymmetric-key:import-key *public-key-operation:rsa* pub-key-asn))
  (define (verify sig)
    (let ((s (verifier-descriptor:init rsa-verifier-descriptor pub-key param)))
      (verifier-descriptor:process! rsa-verifier-descriptor s msg)
      (test-assert (verifier-descriptor:verify rsa-verifier-descriptor s sig))))
  (verify sig))


(test-rsa-emsa-pss (hex-string->bytevector "3082010a0282010100bd31c7a02691d2d9587ef6a946ff788544ccadd4b2988ad62086792a6bf96c8616b4ad13317d2270b901d0fcd1d880cb8f52fb87304a5258c11b38dfeae8df670aeee7ea1d0d9df8e00e80847e41e5989ed402d44e78b30fef17b5671d3adbf8685e4dc204499ecd1863e1d5aff28a7cf66eadf31fec9236c120add13451522c647c9832a672cd64d328c1c322183f4661d09bda60b8dd5f0328da5420821424afdabb1a80c5d12763a1b0238cd89d0742bfc50b6a2fcb701d824218f9826f4f78a23a2b5aa42ace7f175376fb6cbdb2bad293ba583d4d31c6b8f9029e46b13689249855f505756e00e225a6a45a18769bd8d2b3a4acb9f1c23d3e51882561e50203010001")
		   #vu8()
		   (hex-string->bytevector "1d5a9bb49cb1f5c2862f36e451dce7fc607f3d302eb9a9fbea5b673a29fa9023308381262c538cb53910b5773a7a44ff465828bdfccf8a7a4ef902e945dd5f6226ffb7d5b05f2335e5762c5aceff71c8408150959c1780cc9c22fccebd3405e81f1bc16d276c07e4a545ddb1aadeb751b571d22f3e4bc4e02020eec5901a1ebc04415e9ddfe967fbe4ec7166923aa095b9fc7a81fc21ba37b5220a973fc5f32fdb8e0841ed321450248402a159d2c08e4a72b780310d420a6e499c2b34b0bd6fe0d1d0e1a7810563324ad8e778720755eb00ac6e28b204ff5fbb01fcfc91e8f1d2f113a5f32843119f5e06beec0fe94e5bfd0ccdd7f322bdab7b05c4f83c0504")
		   (make-signature-parameter
		    (make-rsa-signature-verify-parameter pkcs1-emsa-pss-verify)
		    (make-signature-digest-parameter *digest:sha1*)))

(test-rsa-emsa-pss (hex-string->bytevector "3082010a0282010100bd31c7a02691d2d9587ef6a946ff788544ccadd4b2988ad62086792a6bf96c8616b4ad13317d2270b901d0fcd1d880cb8f52fb87304a5258c11b38dfeae8df670aeee7ea1d0d9df8e00e80847e41e5989ed402d44e78b30fef17b5671d3adbf8685e4dc204499ecd1863e1d5aff28a7cf66eadf31fec9236c120add13451522c647c9832a672cd64d328c1c322183f4661d09bda60b8dd5f0328da5420821424afdabb1a80c5d12763a1b0238cd89d0742bfc50b6a2fcb701d824218f9826f4f78a23a2b5aa42ace7f175376fb6cbdb2bad293ba583d4d31c6b8f9029e46b13689249855f505756e00e225a6a45a18769bd8d2b3a4acb9f1c23d3e51882561e50203010001")
		   (hex-string->bytevector "0000000000000000000000000000000000000000")
		   (hex-string->bytevector "01e9b1d4f36d040a553ee12afb76a36d04c6c5a0f3df84ae22422e8157e57b1c43a7bdaade30ae73073632a4679973ec10bcbb3016f6e20c9cad29a14f96052507819e90cf56ba50c97df5e5001c7f94817ed29f7500f839eb415ef3182aedb2484bace43cd2fcaaa6f5dbc4b6491791592f084b2a14ab303e89deb28a68c72b0b630ae85becb67f2b722f23a0f321f3a7496b251895111640452932579aa53ffb8f8fb4ffd331fa48c6f1e8e152ce7e04cfec941cd96dcf7a885a3022e426d87e8111336f1166878dcf8d190ffb16a574fea9eb6d7e270e025c6d98817e75c968f78c4750be018f74968d7f3e5cb9d6f47d5aafc99c85c83af7175c73091ae8")
		   (make-signature-parameter
		    (make-rsa-signature-verify-parameter pkcs1-emsa-pss-verify)
		    (make-signature-digest-parameter *digest:sha1*)))

;; from https://github.com/google/wycheproof/blob/master/testvectors/rsa_pss_2048_sha256_mgf1_0_test.json 
(test-rsa-emsa-pss (hex-string->bytevector "3082010a0282010100a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9d50203010001")
		   #vu8()
		   (hex-string->bytevector "20081f8894a1330c4d503f642880e3c30e398fc6235c24f1be752e2d49cd9493ac0cf999e275c4f89ff08f0d9ba4e264a332525a616d336bd9e822f41ab3f4fae2f48ec66c2e52642ed93b7cb944396fbaa727cbfdfc1f20aace99a6f2a74475c338f8d9f22a38cb5bc51752076503b3aef1e65e5a8f8583d9ae7378ded038cf516898ad06beb90a42b85764526fcea44f74258fa4efb1da253d337f65619181ceb832dfe285ce78ae6b15f204e23bab274e87445d9f5df97f41dc8e3a97736b62591d075744b2552f90bcf1b1393e1e7627ef1f985f2bbabd52e43a35d0ddf4c67126e391f922ef7b1bb1911cd6e1b303cb2910dd70672bbfb62ea4eaad725c")
		   (make-signature-parameter
		    (make-rsa-signature-verify-parameter pkcs1-emsa-pss-verify)
		    (make-rsa-signature-mgf-digest-parameter *digest:sha256*)
		    (make-rsa-signature-salt-length-parameter 0)
		    (make-signature-digest-parameter *digest:sha256*)))

(define (test-rsa-emsa-pss-sign priv-key pub-key msg param)
  (define (verify sig)
    (let ((s (verifier-descriptor:init rsa-verifier-descriptor pub-key param)))
      (verifier-descriptor:process! rsa-verifier-descriptor s msg)
      (test-assert (verifier-descriptor:verify rsa-verifier-descriptor s sig))))
  (define (sign)
    (let ((state (signer-descriptor:init rsa-signer-descriptor priv-key param)))
      (signer-descriptor:process! rsa-signer-descriptor state msg)
      (signer-descriptor:sign rsa-signer-descriptor state)))
  (verify (sign)))
(test-rsa-emsa-pss-sign private-key public-key #vu8()
			(make-signature-parameter
			 (make-rsa-signature-encode-parameter pkcs1-emsa-pss-encode)
			 (make-rsa-signature-verify-parameter pkcs1-emsa-pss-verify)
			 (make-signature-digest-parameter *digest:sha1*)))
(test-rsa-emsa-pss-sign private-key public-key #vu8()
			(make-signature-parameter
			 (make-rsa-signature-encode-parameter pkcs1-emsa-pss-encode)
			 (make-rsa-signature-verify-parameter pkcs1-emsa-pss-verify)
			 (make-rsa-signature-mgf-digest-parameter *digest:sha256*)
			 (make-rsa-signature-salt-length-parameter 0)
			 (make-rsa-signature-salt-parameter #vu8())
			 (make-signature-digest-parameter *digest:sha256*)))

(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
