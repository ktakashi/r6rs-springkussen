(import (rnrs)
	(springkussen conditions)
	(springkussen cipher symmetric)
	(srfi :64)
	(testing))

(test-begin "Symmetric cipher APIs")

(define (test-encrypt/decrypt cipher-spec key pt . opt)
  (define param (and (not (null? opt)) (car opt)))
  (define cipher (make-symmetric-cipher cipher-spec))
  (let ((ct (symmetric-cipher:encrypt-bytevector cipher key param pt)))
    (test-assert "Plain text != cipher text" (not (bytevector=? pt ct)))
    (test-equal "Decrypt"
		pt (symmetric-cipher:decrypt-bytevector cipher key param ct))))

(test-assert (symmetric-cipher-spec?
	      (symmetric-cipher-spec-builder (scheme *scheme:aes*)
					     (mode *mode:ecb*))))
(test-error springkussen-condition?
	    (symmetric-cipher-spec-builder (mode *mode:ecb*)))
(test-error springkussen-condition?
	    (symmetric-cipher-spec-builder (scheme *scheme:aes*)))

(test-assert "Enc scheme" (symmetric-scheme-descriptor? *scheme:aes*))
(test-equal 16 (symmetric-scheme-descriptor-block-size *scheme:aes*))
(test-assert "Enc scheme" (symmetric-scheme-descriptor? *scheme:aes-128*))
(test-assert "Enc scheme" (symmetric-scheme-descriptor? *scheme:aes-192*))
(test-assert "Enc scheme" (symmetric-scheme-descriptor? *scheme:aes-256*))
(test-assert "Enc scheme" (symmetric-scheme-descriptor? *scheme:des*))
(test-assert "Enc scheme" (symmetric-scheme-descriptor? *scheme:desede*))
(test-assert "Enc scheme" (symmetric-scheme-descriptor? *scheme:rc2*))
(test-assert "Enc scheme" (symmetric-scheme-descriptor? *scheme:rc5*))

(test-assert "Enc mode" (symmetric-mode-descriptor? *mode:ecb*))
(test-assert "Enc mode" (symmetric-mode-descriptor? *mode:cbc*))

(test-assert "Mode parameter" (mode-parameter? (make-iv-paramater #vu8())))
(test-assert "Cipher parameter"
	     (cipher-parameter?
	      (make-cipher-parameter (make-iv-paramater #vu8()))))

(test-assert "Symmetric key" (symmetric-key? (make-symmetric-key #vu8())))

;; AES/ECB
(let ((aes-ecb-cipher-spec (symmetric-cipher-spec-builder
			    (scheme *scheme:aes*)
			    (mode *mode:ecb*))))
  (test-encrypt/decrypt aes-ecb-cipher-spec
			(make-symmetric-key
			 #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))
			;; non block size
			#vu8(1 2 3 4 5 6 7 8 9 10)))
;; AES/CBC
(let ((aes-cbc-cipher-spec (symmetric-cipher-spec-builder
			    (scheme *scheme:aes*)
			    (mode *mode:cbc*)))
      (key (make-symmetric-key
	    #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))))
  (test-encrypt/decrypt aes-cbc-cipher-spec key
			#vu8(1 2 3 4 5 6 7 8 9 10)
			(make-iv-paramater
			 #vu8(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
  ;; parameter modification
  (let* ((iv (make-bytevector 16 0))
	 (param (make-iv-paramater iv))
	 (pt #vu8(1 2 3 4 5 6 7 8 9 10)))
    (let ((enc0 (symmetric-cipher:encrypt-bytevector
		 (make-symmetric-cipher aes-cbc-cipher-spec) key param pt)))
      (bytevector-u8-set! iv 0 1)
      (let ((enc1 (symmetric-cipher:encrypt-bytevector
		   (make-symmetric-cipher aes-cbc-cipher-spec) key param pt)))
	(test-equal enc0 enc1))))
  )

;; Found bug on CBC...
(let ()
  (define aes/cbc 
    (symmetric-cipher-spec-builder
     (scheme *scheme:aes*)
     (mode   *mode:cbc*)))

  (define cipher-mode-parameter
    (make-cipher-parameter
     (make-iv-paramater
      ;; IV must be the same as the block size.
      ;; NOTE: this is an example, so don't use this in production code.
      ;;       IV must be generated properly with secure random generator
      (make-bytevector (symmetric-scheme-descriptor-block-size *scheme:aes*) 0))))

  ;; AES uses key size of 16 bytes to 32 bytes, but here we use 16
  (define key (make-symmetric-key #vu8(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)))
  (define cipher (make-symmetric-cipher aes/cbc))
  (define (encrypt-text key text)
    (symmetric-cipher:encrypt-bytevector cipher key cipher-mode-parameter
					 (string->utf8 text)))

  (define (decrypt-text key bv)
    (utf8->string
     (symmetric-cipher:decrypt-bytevector cipher key cipher-mode-parameter bv)))

  (let ((text "Jumping on Springkussen"))
    (test-equal text (decrypt-text key (encrypt-text key text)))))

;; multiblock CBC
(define (test-cbc-multi-blocks name scheme key iv pt ct)
  (define spec (symmetric-cipher-spec-builder
		(scheme scheme)
		(mode *mode:cbc*)
		(padding no-padding)))
  (define param (make-iv-paramater iv))
  (define cipher (make-symmetric-cipher spec))
  (define skey (make-symmetric-key key))
  (let ((bv (symmetric-cipher:encrypt-bytevector cipher skey param pt)))
    (test-equal (string-append name " enc") ct bv)
    (test-equal (string-append name " dec") pt
		(symmetric-cipher:decrypt-bytevector cipher skey param ct))))

(define (parse-multiple-block-test e scheme)
  (define (ref name e) (cadr (assq name e)))
  (let ((name (string-append (symmetric-scheme-descriptor-name scheme)
			     " (" (ref 'COUNT e) ")"))
	(key (hex-string->bytevector (ref 'KEY e)))
	(iv (hex-string->bytevector (ref 'IV e)))
	(pt (hex-string->bytevector (ref 'PLAINTEXT e)))
	(ct (hex-string->bytevector (ref 'CIPHERTEXT e))))
    (test-cbc-multi-blocks name scheme key iv pt ct)))

(define aes-test-vectors
  '((
     (COUNT "0")
     (KEY "1f8e4973953f3fb0bd6b16662e9a3c17")
     (IV "2fe2b333ceda8f98f4a99b40d2cd34a8")
     (PLAINTEXT "45cf12964fc824ab76616ae2f4bf0822")
     (CIPHERTEXT "0f61c4d44c5147c03c195ad7e2cc12b2")
     )
    (
     (COUNT "1")
     (KEY "0700d603a1c514e46b6191ba430a3a0c")
     (IV "aad1583cd91365e3bb2f0c3430d065bb")
     (PLAINTEXT "068b25c7bfb1f8bdd4cfc908f69dffc5ddc726a197f0e5f720f730393279be91")
     (CIPHERTEXT "c4dc61d9725967a3020104a9738f23868527ce839aab1752fd8bdb95a82c4d00")
     )
    (
     (COUNT "2")
     (KEY "3348aa51e9a45c2dbe33ccc47f96e8de")
     (IV "19153c673160df2b1d38c28060e59b96")
     (PLAINTEXT "9b7cee827a26575afdbb7c7a329f887238052e3601a7917456ba61251c214763d5e1847a6ad5d54127a399ab07ee3599")
     (CIPHERTEXT "d5aed6c9622ec451a15db12819952b6752501cf05cdbf8cda34a457726ded97818e1f127a28d72db5652749f0c6afee5")
     )
    (
     (COUNT "3")
     (KEY "b7f3c9576e12dd0db63e8f8fac2b9a39")
     (IV "c80f095d8bb1a060699f7c19974a1aa0")
     (PLAINTEXT "9ac19954ce1319b354d3220460f71c1e373f1cd336240881160cfde46ebfed2e791e8d5a1a136ebd1dc469dec00c4187722b841cdabcb22c1be8a14657da200e")
     (CIPHERTEXT "19b9609772c63f338608bf6eb52ca10be65097f89c1e0905c42401fd47791ae2c5440b2d473116ca78bd9ff2fb6015cfd316524eae7dcb95ae738ebeae84a467")
     )
    (
     (COUNT "4")
     (KEY "b6f9afbfe5a1562bba1368fc72ac9d9c")
     (IV "3f9d5ebe250ee7ce384b0d00ee849322")
     (PLAINTEXT "db397ec22718dbffb9c9d13de0efcd4611bf792be4fce0dc5f25d4f577ed8cdbd4eb9208d593dda3d4653954ab64f05676caa3ce9bfa795b08b67ceebc923fdc89a8c431188e9e482d8553982cf304d1")
     (CIPHERTEXT "10ea27b19e16b93af169c4a88e06e35c99d8b420980b058e34b4b8f132b13766f72728202b089f428fecdb41c79f8aa0d0ef68f5786481cca29e2126f69bc14160f1ae2187878ba5c49cf3961e1b7ee9")
     )
    (
     (COUNT "5")
     (KEY "bbe7b7ba07124ff1ae7c3416fe8b465e")
     (IV "7f65b5ee3630bed6b84202d97fb97a1e")
     (PLAINTEXT "2aad0c2c4306568bad7447460fd3dac054346d26feddbc9abd9110914011b4794be2a9a00a519a51a5b5124014f4ed2735480db21b434e99a911bb0b60fe0253763725b628d5739a5117b7ee3aefafc5b4c1bf446467e7bf5f78f31ff7caf187")
     (CIPHERTEXT "3b8611bfc4973c5cd8e982b073b33184cd26110159172e44988eb5ff5661a1e16fad67258fcbfee55469267a12dc374893b4e3533d36f5634c3095583596f135aa8cd1138dc898bc5651ee35a92ebf89ab6aeb5366653bc60a70e0074fc11efe")
     )
    (
     (COUNT "6")
     (KEY "89a553730433f7e6d67d16d373bd5360")
     (IV "f724558db3433a523f4e51a5bea70497")
     (PLAINTEXT "807bc4ea684eedcfdcca30180680b0f1ae2814f35f36d053c5aea6595a386c1442770f4d7297d8b91825ee7237241da8925dd594ccf676aecd46ca2068e8d37a3a0ec8a7d5185a201e663b5ff36ae197110188a23503763b8218826d23ced74b31e9f6e2d7fbfa6cb43420c7807a8625")
     (CIPHERTEXT "406af1429a478c3d07e555c5287a60500d37fc39b68e5bbb9bafd6ddb223828561d6171a308d5b1a4551e8a5e7d572918d25c968d3871848d2f16635caa9847f38590b1df58ab5efb985f2c66cfaf86f61b3f9c0afad6c963c49cee9b8bc81a2ddb06c967f325515a4849eec37ce721a")
     )
    (
     (COUNT "7")
     (KEY "c491ca31f91708458e29a925ec558d78")
     (IV "9ef934946e5cd0ae97bd58532cb49381")
     (PLAINTEXT "cb6a787e0dec56f9a165957f81af336ca6b40785d9e94093c6190e5152649f882e874d79ac5e167bd2a74ce5ae088d2ee854f6539e0a94796b1e1bd4c9fcdbc79acbef4d01eeb89776d18af71ae2a4fc47dd66df6c4dbe1d1850e466549a47b636bcc7c2b3a62495b56bb67b6d455f1eebd9bfefecbca6c7f335cfce9b45cb9d")
     (CIPHERTEXT "7b2931f5855f717145e00f152a9f4794359b1ffcb3e55f594e33098b51c23a6c74a06c1d94fded7fd2ae42c7db7acaef5844cb33aeddc6852585ed0020a6699d2cb53809cefd169148ce42292afab063443978306c582c18b9ce0da3d084ce4d3c482cfd8fcf1a85084e89fb88b40a084d5e972466d07666126fb761f84078f2")
     )
    (
     (COUNT "8")
     (KEY "f6e87d71b0104d6eb06a68dc6a71f498")
     (IV "1c245f26195b76ebebc2edcac412a2f8")
     (PLAINTEXT "f82bef3c73a6f7f80db285726d691db6bf55eec25a859d3ba0e0445f26b9bb3b16a3161ed1866e4dd8f2e5f8ecb4e46d74a7a78c20cdfc7bcc9e479ba7a0caba9438238ad0c01651d5d98de37f03ddce6e6b4bd4ab03cf9e8ed818aedfa1cf963b932067b97d776dce1087196e7e913f7448e38244509f0caf36bd8217e15336d35c149fd4e41707893fdb84014f8729")
     (CIPHERTEXT "b09512f3eff9ed0d85890983a73dadbb7c3678d52581be64a8a8fc586f490f2521297a478a0598040ebd0f5509fafb0969f9d9e600eaef33b1b93eed99687b167f89a5065aac439ce46f3b8d22d30865e64e45ef8cd30b6984353a844a11c8cd60dba0e8866b3ee30d24b3fa8a643b328353e06010fa8273c8fd54ef0a2b6930e5520aae5cd5902f9b86a33592ca4365")
     )
    (
     (COUNT "9")
     (KEY "2c14413751c31e2730570ba3361c786b")
     (IV "1dbbeb2f19abb448af849796244a19d7")
     (PLAINTEXT "40d930f9a05334d9816fe204999c3f82a03f6a0457a8c475c94553d1d116693adc618049f0a769a2eed6a6cb14c0143ec5cccdbc8dec4ce560cfd206225709326d4de7948e54d603d01b12d7fed752fb23f1aa4494fbb00130e9ded4e77e37c079042d828040c325b1a5efd15fc842e44014ca4374bf38f3c3fc3ee327733b0c8aee1abcd055772f18dc04603f7b2c1ea69ff662361f2be0a171bbdcea1e5d3f")
     (CIPHERTEXT "6be8a12800455a320538853e0cba31bd2d80ea0c85164a4c5c261ae485417d93effe2ebc0d0a0b51d6ea18633d210cf63c0c4ddbc27607f2e81ed9113191ef86d56f3b99be6c415a4150299fb846ce7160b40b63baf1179d19275a2e83698376d28b92548c68e06e6d994e2c1501ed297014e702cdefee2f656447706009614d801de1caaf73f8b7fa56cf1ba94b631933bbe577624380850f117435a0355b2b")
     )))

(for-each (lambda (e) (parse-multiple-block-test e *scheme:aes-128*))
	  aes-test-vectors)

(define des3-test-vectors
  '(
    (
     (COUNT "0")
     (KEY "46133dcbf232b51964e0d95e83208f156732bf75b673abf1")
     (IV "34814c87f47fd59d")
     (PLAINTEXT "de655a0ea771436c")
     (CIPHERTEXT "092368405296744a")
     )
    (
     (COUNT "1")
     (KEY "6d0d67da68ab166d1f43c7204c4c2aa4c81a528515f1dff2")
     (IV "68e63a07b22e33eb")
     (PLAINTEXT "4346c4e81380626fa0b2776d30a4fc05")
     (CIPHERTEXT "5274be183f5dfb6b018f22b322f0392d")
     )
    (
     (COUNT "2")
     (KEY "134cb3efe62a4ad552cb85a164fee6b964a1269b193d68c4")
     (IV "0fa311f99ec57b86")
     (PLAINTEXT "1b735b0557255a0e6d8d675879e7201ca34c8761a129a914")
     (CIPHERTEXT "2f1ac7ee1414af15587cb2c540401294028e1e39d1cf2f67")
     )
    (
     (COUNT "3")
     (KEY "202398b6154968c168201329910e612f296189d320670120")
     (IV "514273c93806fde6")
     (PLAINTEXT "9a5ec913876299492dda3998f88e1c31a75493b3ade14e9ed7de1f0a303f0299")
     (CIPHERTEXT "9bc02247ff5cefde9a0307f948f9437ef2a298cdd69542236cba47e8c954e819")
     )
    (
     (COUNT "4")
     (KEY "199476c24302b6ab0b98d5a807079e4337e68f5ec77561ab")
     (IV "6e06875955b87f87")
     (PLAINTEXT "420fdffb706770ba1aee85bb992ed2efe7c4cb10a75cc03565dd4da41ee1f1e70368fd227acdb0a3")
     (CIPHERTEXT "f390d5afc5969d63d9c0a95e1f1c290d0bd29510e8e982502faa7ed616cfe873af88b27a7b62cb21")
     )
    (
     (COUNT "5")
     (KEY "323bf24fe0ad70943e70bf1c5df4d531dc0d926e83804c4a")
     (IV "298558d95517a045")
     (PLAINTEXT "26e44aa78fcc690687e74cfdfcbd6ef34696011e5ae1cbfe40d6332bc75b9c517724f179c71f818a900f0e0fc276203a")
     (CIPHERTEXT "d09b9568877769780fda9911c29b303b27e15b5f29b2ddf89c3b7edcc04dee78b751d459a50df3ae57bffd4b4ca41fc4")
     )
    (
     (COUNT "6")
     (KEY "f7a494c27326734a104525041052103ef2680e3bd35ea158")
     (IV "a5fe08d9045bbf88")
     (PLAINTEXT "f9117249047fb9fe884c89267e5ac96314f233d201c14d3315209a4a14991184c4a6cede45bb0803a18743b4a478c66dee7d5046460f0717")
     (CIPHERTEXT "c89ff7bcc5558952e8614a7bfcf8a1b017f040ef954f6552696ae53b70e6f953ba6d9d0efe381c2bdd54d911ad6eac5b0ce2845341ae3458")
     )
    (
     (COUNT "7")
     (KEY "d3318958c78cfd98c7ae312a2c08bcfefd10269729013de5")
     (IV "01b6dd4a4c96349a")
     (PLAINTEXT "83577346841a1bbf08fb6d2be351f33914efc8ef9aa7054b890d7c2b5c7da96a8d60e54c63aadd1c0ca74313ebf8c37c33d93916b5a521baf69b4e3d85e2e098")
     (CIPHERTEXT "8be30ca745a06e2f67c3ec2ed18e872028448597218b007746d954da0ba6b3db20f9a28d7faea32ee3f13103dc8018e8f97dc2c348d2966c9e2b87b0f318e026")
     )
    (
     (COUNT "8")
     (KEY "a4e50d8a1f64f4d9f41a8ad0a8c868b34ac861dc4c38fd89")
     (IV "f21047a08a1bed96")
     (PLAINTEXT "fa7c94a2eb67dbf0ce8e30d5b944e9585ffef8b9d807cabda0756f46e15bfa26f5402b3526d04ba2b9d258862c5a62bfbb4035fb29d03813bcc3959b8a6f9ab7f33a602f6f54aac6")
     (CIPHERTEXT "e4025b1f5bcde6eae6c7bbfd4851258af6d097791a02d8df5483a8cbcfeaaf52dddb61bf1ddc52b9cb6df947cb0492489036212543fab82694449c8d3d323dce016e2648ac6f653e")
     )
    (
     (COUNT "9")
     (KEY "08763da862ad16ef5815408f5d3b705415ab1543a42c3efb")
     (IV "0634d69eaff3ae17")
     (PLAINTEXT "109a3d3d745d65b38edbc73d1de8b2807f7820221a6c3937faab19fcbb75d3c8aaf4b63f2714cfc94e95ae43d65f6df43815efc214ec66a5d1be185d855a6260141ffd179bc980490f8a26d8215dd2ab")
     (CIPHERTEXT "e9513e8892a09085bee29c358014afd60d7578d21e00a31e5d61b965c18778ebe18469170794e5ddf24aa777c8ab0a2c62474109e617978bcc5ce3456ddd9622833420443c2a26b1b6e20a05c189da6c")
     )
    )
  )
(for-each (lambda (e) (parse-multiple-block-test e *scheme:desede*))
	  des3-test-vectors)


(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
