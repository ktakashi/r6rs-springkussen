#!r6rs
(import (rnrs)
	(springkussen cipher key)
	(springkussen cipher asymmetric key)
	(springkussen signature ecdsa)
	(springkussen signature descriptor)
	(springkussen signature parameters)
	(springkussen math ec)
	(springkussen digest)
	(srfi :64)
	(testing))

(test-begin "ECDSA")

(define test-ecdsa-verify
  (case-lambda
   ((x y ec-param digest msg S)
    (test-ecdsa-verify x y ec-param digest msg S #t))
   ((x y ec-param digest msg S valid?)
    (test-ecdsa-verify x y ec-param digest msg S valid? 'none))
   ((x y ec-param digest msg S valid? encode)
    (define key (key-factory:generate-key *ecdsa-key-factory*
		 (make-key-parameter
		  (make-ecdsa-ec-parameter ec-param)
		  (make-ecdsa-public-key-parameter x y))))
    (test-assert (ecdsa-public-key? key))
    (test-equal (make-ec-point x y) (ecdsa-public-key-Q key))
    (test-equal ec-param (ecdsa-public-key-ec-parameter key))

    (let* ((param (make-signature-parameter
		   (make-signature-digest-parameter digest)
		   (make-ecdsa-encode-parameter encode)))
	   (st (verifier-descriptor:init ecdsa-verifier-descriptor key param)))
      (verifier-descriptor:process! ecdsa-verifier-descriptor st msg)
      (let ((r (verifier-descriptor:verify ecdsa-verifier-descriptor st S)))
      (if valid?
	  (test-assert r)
	  (test-assert (not r))))))))

;; Test vectors are from
;; https://github.com/google/wycheproof/blob/master/testvectors/ecdsa_secp224r1_sha224_p1363_test.json
(test-ecdsa-verify #x00eada93be10b2449e1e8bb58305d52008013c57107c1a20a317a6cba7
		   #x00eca672340c03d1d2e09663286691df55069fa25490c9dd9f9c0bb2b5
		   secp224r1
		   *digest:sha224*
		   (hex-string->bytevector "313233343030")
		   (hex-string->bytevector "70049af31f8348673d56cece2b27e587a402f2a48f0b21a7911a480a2840bf24f6f66be287066b7cbf38788e1b7770b18fd1aa6a26d7c6dc"))

(test-ecdsa-verify #x00eada93be10b2449e1e8bb58305d52008013c57107c1a20a317a6cba7
		   #x00eca672340c03d1d2e09663286691df55069fa25490c9dd9f9c0bb2b5
		   secp224r1
		   *digest:sha224*
		   (hex-string->bytevector "313233343030")
		   (hex-string->bytevector "0170049af31f8348673d56cece2b26fc2a84bbe2e2a2e84aeced76724700d7bf40db0909941d78f9948340c69e14c5417f8c840b7edb35846361")
		   #f)

(test-ecdsa-verify #x00eada93be10b2449e1e8bb58305d52008013c57107c1a20a317a6cba7
		   #x00eca672340c03d1d2e09663286691df55069fa25490c9dd9f9c0bb2b5
		   secp224r1
		   *digest:sha224*
		   (hex-string->bytevector "313233343030")
		   (hex-string->bytevector "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
		   #f)

(test-ecdsa-verify #x00eada93be10b2449e1e8bb58305d52008013c57107c1a20a317a6cba7
		   #x00eca672340c03d1d2e09663286691df55069fa25490c9dd9f9c0bb2b5
		   secp224r1
		   *digest:sha224*
		   (hex-string->bytevector "313233343030")
		   (hex-string->bytevector "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001")
		   #f)

(test-ecdsa-verify #x00eada93be10b2449e1e8bb58305d52008013c57107c1a20a317a6cba7
		   #x00eca672340c03d1d2e09663286691df55069fa25490c9dd9f9c0bb2b5
		   secp224r1
		   *digest:sha224*
		   (hex-string->bytevector "313233343030")
		   (hex-string->bytevector "00000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d")
		   #f)

(test-ecdsa-verify #x00eada93be10b2449e1e8bb58305d52008013c57107c1a20a317a6cba7
		   #x00eca672340c03d1d2e09663286691df55069fa25490c9dd9f9c0bb2b5
		   secp224r1
		   *digest:sha224*
		   (hex-string->bytevector "313233343030")
		   (hex-string->bytevector "00000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3c")
		   #f)

(test-ecdsa-verify #x00eada93be10b2449e1e8bb58305d52008013c57107c1a20a317a6cba7
		   #x00eca672340c03d1d2e09663286691df55069fa25490c9dd9f9c0bb2b5
		   secp224r1
		   *digest:sha224*
		   (hex-string->bytevector "313233343030")
		   (hex-string->bytevector "00000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3e")
		   #f)

(test-ecdsa-verify #x00eada93be10b2449e1e8bb58305d52008013c57107c1a20a317a6cba7
		   #x00eca672340c03d1d2e09663286691df55069fa25490c9dd9f9c0bb2b5
		   secp224r1
		   *digest:sha224*
		   (hex-string->bytevector "313233343030")
		   (hex-string->bytevector "00000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffff0000000000000000000000000001")
		   #f)

(test-ecdsa-verify #x00eada93be10b2449e1e8bb58305d52008013c57107c1a20a317a6cba7
		   #x00eca672340c03d1d2e09663286691df55069fa25490c9dd9f9c0bb2b5
		   secp224r1
		   *digest:sha224*
		   (hex-string->bytevector "313233343030")
		   (hex-string->bytevector "00000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffff0000000000000000000000000002")
		   #f)

(test-ecdsa-verify #x00eada93be10b2449e1e8bb58305d52008013c57107c1a20a317a6cba7
		   #x00eca672340c03d1d2e09663286691df55069fa25490c9dd9f9c0bb2b5
		   secp224r1
		   *digest:sha224*
		   (hex-string->bytevector "313233343030")
		   (hex-string->bytevector "0000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000")
		   #f)

(test-ecdsa-verify #x00eada93be10b2449e1e8bb58305d52008013c57107c1a20a317a6cba7
		   #x00eca672340c03d1d2e09663286691df55069fa25490c9dd9f9c0bb2b5
		   secp224r1
		   *digest:sha224*
		   (hex-string->bytevector "313233343030")
		   (hex-string->bytevector "0000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000001")
		   #f)

(test-ecdsa-verify #x00eada93be10b2449e1e8bb58305d52008013c57107c1a20a317a6cba7
		   #x00eca672340c03d1d2e09663286691df55069fa25490c9dd9f9c0bb2b5
		   secp224r1
		   *digest:sha224*
		   (hex-string->bytevector "3137353738")
		   (hex-string->bytevector "326bc06353f7f9c9f77b8f4b55464e8619944e7879402cca572e041a3116e1a38e4ab2008eca032fb2d185e5c21a232eaf4507ae56177fd2"))

;; https://github.com/google/wycheproof/blob/master/testvectors/ecdsa_secp256k1_sha256_p1363_test.json
(test-ecdsa-verify #x00b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f
		   #x00f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9
		   secp256k1
		   *digest:sha256*
		   (hex-string->bytevector "313233343030")
		   (hex-string->bytevector "813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87"))

(test-ecdsa-verify #x00b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f
		   #x00f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9
		   secp256k1
		   *digest:sha256*
		   (hex-string->bytevector "313233343030")
		   (hex-string->bytevector "01813ef79ccefa9a56f7ba805f0e478583b90deabca4b05c4574e49b5899b964a6006ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba")
		   #f)

(test-ecdsa-verify #x00b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f
		   #x00f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9
		   secp256k1
		   *digest:sha256*
		   (hex-string->bytevector "313233343030")
		   (hex-string->bytevector "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
		   #f)

;; secp224k1
(test-ecdsa-verify #x4f2973fc101dd4a313a3a26ac90e2ec4087d1930e87a8e4605739606
		   #xae5ee060ea5f6f5bcb211b2bc2266efc70148d2c1da3910498f9aaa
		   secp224k1
		   *digest:sha224*
		   #vu8()
		   (hex-string->bytevector "303d021c2ff6371550a8d769ff3cccaf7d5b651b43f6a969d665d74ec37a8f5b021d00a4252b9290689676ac040b7f363c7be123f8bcffcb1b0932ec678b8e")
		   #t
		   'der)

(define (test-ecdsa-sign ec-parameter md)
  (define kp (key-pair-factory:generate-key-pair *ecdsa-key-pair-factory*
	      (make-ecdsa-ec-parameter ec-parameter)))
  (define (sign msg der?)
    (let* ((encode-type (if der?
			    (ecdsa-signature-encode-type der)
			    (ecdsa-signature-encode-type none)))
	   (st (signer-descriptor:init ecdsa-signer-descriptor
		(key-pair-private kp)
		(make-signature-parameter
		 (make-signature-digest-parameter md)
		 (make-ecdsa-encode-parameter encode-type)))))
      (signer-descriptor:process! ecdsa-signer-descriptor st msg)
      (signer-descriptor:sign ecdsa-signer-descriptor st)))
  (define (verify msg S der?)
    (let* ((encode-type (if der?
			    (ecdsa-signature-encode-type der)
			    (ecdsa-signature-encode-type none)))
	   (st (verifier-descriptor:init ecdsa-verifier-descriptor
		(key-pair-public kp)
		(make-signature-parameter
		 (make-signature-digest-parameter md)
		 (make-ecdsa-encode-parameter encode-type)))))
      (verifier-descriptor:process! ecdsa-verifier-descriptor st msg)
      (verifier-descriptor:verify ecdsa-verifier-descriptor st S)))

  (define (check msg)
    (test-assert msg (verify msg (sign msg #t) #t))
    (test-assert msg (verify msg (sign msg #f) #f)))
  (check #vu8())
  (check #vu8(1))
  (check (string->utf8 "Hello Springkussen")))

(for-each (lambda (ec-parameter)
	    (for-each (lambda (md) (test-ecdsa-sign ec-parameter md))
		      ;; If we test all digests, it won't finish in
		      ;; reasonable time, so only sha-224.
		      (list ;; *digest:sha1*
			    *digest:sha224*
			    ;; *digest:sha256*
			    ;; *digest:sha384*
			    ;; *digest:sha512*
			    ;; *digest:sha512/224*
			    ;; *digest:sha512/256*
			    )))
	  ;; over 400 is commented out due to the too long execution time...
	  (list NIST-P-192
		NIST-P-224
		NIST-P-256
		NIST-P-384
		;; NIST-P-521
		NIST-K-163
		NIST-K-233
		NIST-K-283
		;; NIST-K-409
		;; NIST-K-571
		NIST-B-163
		NIST-B-233
		NIST-B-283
		;; NIST-B-409
		;; NIST-B-571
		;; The below are renaming, so no need for testing
		;; secp192r1
		;; secp224r1
		;; secp256r1
		;; secp384r1
		;; secp521r1
		;; sect163k1
		;; sect233k1
		;; sect283k1
		;; sect409k1
		;; sect571k1
		;; sect163r2
		;; sect233r1
		;; sect283r1
		;; sect409r1
		;; sect571r1
		secp192k1
		secp224k1
		secp256k1
		sect163r1
		sect239k1
		sect113r1))

(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
