#!r6rs
(import (rnrs)
	(springkussen cipher key)
	(springkussen cipher asymmetric)
	(springkussen conditions)
	(srfi :64)
	(testing))

(test-begin "Asymmetric cipher")

(test-assert (key-factory? *key-factory:rsa*))

(test-assert (key-pair-factory? *key-pair-factory:rsa*))
(define (key-pair-test factory param)
  (let ((kp (key-pair-factory:generate-key-pair factory param)))
    (test-assert (key-pair? kp))
    (test-assert (asymmetric-key? (key-pair-private kp)))
    (test-assert (private-key? (key-pair-private kp)))
    (test-assert (asymmetric-key? (key-pair-public kp)))
    (test-assert (public-key? (key-pair-public kp)))))
(key-pair-test *key-pair-factory:rsa* (make-key-size-key-parameter 1024))
(key-pair-test *key-pair-factory:rsa* #f)

(define (test-asymmetric-ciper pt ct spec pub-key priv-key)
  (define (encrypt pt)
    (define cipher (make-asymmetric-cipher spec pub-key))
    (asymmetric-cipher:encrypt-bytevector cipher pt))
  (define (decrypt ct)
    (define cipher (make-asymmetric-cipher spec priv-key))
    (asymmetric-cipher:decrypt-bytevector cipher ct))

  (test-equal (bytevector->integer pt) (bytevector->integer (decrypt ct)))
  (test-equal (bytevector->integer pt)
	      (bytevector->integer (decrypt (encrypt pt)))))

(define (test-rsa-pkcs1-v1.5 pt ct m e pe p q dp dq qp)
  (define spec (asymmetric-cipher-spec-builder
		(scheme *scheme:rsa*)))
  (let ((pub-key (key-factory:generate-key *key-factory:rsa*
		  (make-rsa-public-key-parameter m e)))
	(priv-key (key-factory:generate-key *key-factory:rsa*
		   (make-rsa-private-key-parameter m pe)))
	(crt-priv-key (key-factory:generate-key *key-factory:rsa*
		       (make-rsa-crt-private-key-parameter
			m pe e p q dp dq qp))))
    (test-asymmetric-ciper pt ct spec pub-key priv-key)
    (test-asymmetric-ciper pt ct spec pub-key crt-priv-key)))

(define (test-rsa-pkcs1-v1.5-invalid-padding ct m e pe p q dp dq qp)
  (define spec (asymmetric-cipher-spec-builder
		(scheme *scheme:rsa*)))
  (define (decrypt ct priv-key)
    (define cipher (make-asymmetric-cipher spec priv-key))
    (asymmetric-cipher:decrypt-bytevector cipher ct))

  (let ((priv-key (key-factory:generate-key *key-factory:rsa*
		   (make-rsa-private-key-parameter m pe)))
	(crt-priv-key (key-factory:generate-key *key-factory:rsa*
		       (make-rsa-crt-private-key-parameter
			m pe e p q dp dq qp))))
    (test-error springkussen-condition? (decrypt ct priv-key))
    (test-error springkussen-condition? (decrypt ct crt-priv-key))))

;; From https://github.com/google/wycheproof/blob/master/testvectors/rsa_pkcs1_2048_test.json
(test-rsa-pkcs1-v1.5 #vu8()
		     (integer->bytevector #x5999ccb0cfdd584a3fd9daf247b9cd7314323f8bba4864258f98c6bafc068fe672641bab25ef5b1a7a2b88f67f12af3ca4fe3c493b2062bbb11ad3b1ba0640025c814326ff50ed52b176bd7f606ea9e209bcdcc67c0a0c4b8ed30b9959c57e90fd1efdf99895e2608095f92caff9070dec900fb96d5ce5efd2b2e66b80cff27d482d242b307cb813e7dc818fce31b67ac9a94501b5bc4621b547ba9d81808dd297d600dfc1a7deeb061570cde8894e398453328740adfd77cf76075a109d41ad296651ac817382424a4907d5a342d06cf19c09d5b37a147dd69045bf7d378e19dbbbbfb25282e3d9a4dc9793c8c32ab5a45c0b43dba4daca367b6eb5f4432a62 2048)
		     #x00b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf861075c677c81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d
		     #x010001
		     #x1a502d0eea6c7b69e21d5839101f705456ed0ef852fb47fe21071f54c5f33c8ceb066c62d727e32d26c58137329f89d3195325b795264c195d85472f7507dbd0961d2951f935a26b34f0ac24d15490e1128a9b7138915bc7dbfa8fe396357131c543ae9c98507368d9ceb08c1c6198a3eda7aea185a0e976cd42c22d00f003d9f19d96ea4c9afcbfe1441ccc802cfb0689f59d804c6a4e4f404c15174745ed6cb8bc88ef0b33ba0d2a80e35e43bc90f350052e72016e75b00d357a381c9c0d467069ca660887c987766349fcc43460b4aa516bce079edd87ba164307b752c277ed9528ad3ba0bf1877349ed3b7966a6c240110409bf4d0fade0c68fdadd847fd
		     #xec125cf37e310a2ff46263b9b2e0629d6390005ec88913d4fb71bd4dd856124498aaeba983d7ba2bd942e64d223feb7a23af4d605efeea6bd70d39afe99d35a3aa15e74a1768778093be0edd4a8d09b2def6dc9b67ff85764625c2e19236db4c401ce30a2572d3ecb4f969b7ad19c522c02d774465676e1a3776c54d6248348b
		     #xc2742abcd9897bd4b0b671f973fc82a8f84abf5705ff88dd41948623afe9dca60dc6543390767feaebeb539576ee8bfa61b5fcbca94a7cef75a09150c540fa9694dd8004ad23718c889049219369c99f4458d4afc148f6f07df87324a96d9cf7b385dd8622414a1832f9f29446f050c2d5a6407649dc41ab70e23b3dcc22c987
		     #x96a9798d250263400bb6277342881627e07cecdf91187b01b89ff47314188a7c20fb24800156d2c85d5666e8df6ceff9f9804ddfad80ff5767de56ecc029c72bf6c717df9f64daafc29acf9dc7908f9a0ad67e20e8949936ccba18d021a2c4febb04349a2b2047c4901385b6e5d0c691d118b33f81802b32ac272ef09e42fad5
		     #x554f41b0b87f68a45722b3be0cf4ab1e165034c1a91002ab8f29e9ef9e2dab6fee7b2455bafb42037e9d2f7e533f348a147412fd72080be7c2633f5d802c91c39e6bcece3e675e59995033c55737020dad9e8b30d04b828adfb9304ad54a11a35a4f50709876ac5b118236ba76a4d7c9a291dd9607b169de1d182385691999f
		     #x1c640189d9bfe8c623833210a76c420c6f44e5d760e259916cec2ae2b156456960fd95e2747660c389562250f055049cfab7e5c3039549384a7a2aaeb1c824d3af709482a8cf9b587022a00b1f0722db50f33cb26dc20dd2245d5265df61ee2983c938c2167dcee121fc4b4479c237e728cf633ab60a8c0ecd04fce7e3baa559)

(test-rsa-pkcs1-v1.5 (integer->bytevector #x0000000000000000000000000000000000000000 20)
		     (integer->bytevector #xa9acec7e58761d9191249ff7ea5db499cadccc51d29f8e7fd0aa2cb9962095626f1cadae29666f04ce2afd4b650be59d071d06446d59107eb508cc60545727b0567dfb4f2f94ca60b939c60be111172f367dfd235516e4a60061648c67f5536650821ac2a60744be3cf6befa8f66e76a3e7c5fbc6dfa4dda55ecbdbffdc98d610de5667a4f485f6168b52bbe470e6014253874ce7b78e509937e0bc5f02857e1ad3cf55139bbe6dc7ac4b1ed5097bf781b7671ca9bb58187aa6c71c58ac0561c5aacf96c35deb24e395b6823de7fc96b8031b5906a34c4dc57e4f1226157b9abd849e1367dda014fbf9ed4ca515a7a04cf87787945007e4f63c0366a5bbc3489 2048)
		     #x00b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf861075c677c81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d
		     #x010001
		     #x1a502d0eea6c7b69e21d5839101f705456ed0ef852fb47fe21071f54c5f33c8ceb066c62d727e32d26c58137329f89d3195325b795264c195d85472f7507dbd0961d2951f935a26b34f0ac24d15490e1128a9b7138915bc7dbfa8fe396357131c543ae9c98507368d9ceb08c1c6198a3eda7aea185a0e976cd42c22d00f003d9f19d96ea4c9afcbfe1441ccc802cfb0689f59d804c6a4e4f404c15174745ed6cb8bc88ef0b33ba0d2a80e35e43bc90f350052e72016e75b00d357a381c9c0d467069ca660887c987766349fcc43460b4aa516bce079edd87ba164307b752c277ed9528ad3ba0bf1877349ed3b7966a6c240110409bf4d0fade0c68fdadd847fd
		     #xec125cf37e310a2ff46263b9b2e0629d6390005ec88913d4fb71bd4dd856124498aaeba983d7ba2bd942e64d223feb7a23af4d605efeea6bd70d39afe99d35a3aa15e74a1768778093be0edd4a8d09b2def6dc9b67ff85764625c2e19236db4c401ce30a2572d3ecb4f969b7ad19c522c02d774465676e1a3776c54d6248348b
		     #xc2742abcd9897bd4b0b671f973fc82a8f84abf5705ff88dd41948623afe9dca60dc6543390767feaebeb539576ee8bfa61b5fcbca94a7cef75a09150c540fa9694dd8004ad23718c889049219369c99f4458d4afc148f6f07df87324a96d9cf7b385dd8622414a1832f9f29446f050c2d5a6407649dc41ab70e23b3dcc22c987
		     #x96a9798d250263400bb6277342881627e07cecdf91187b01b89ff47314188a7c20fb24800156d2c85d5666e8df6ceff9f9804ddfad80ff5767de56ecc029c72bf6c717df9f64daafc29acf9dc7908f9a0ad67e20e8949936ccba18d021a2c4febb04349a2b2047c4901385b6e5d0c691d118b33f81802b32ac272ef09e42fad5
		     #x554f41b0b87f68a45722b3be0cf4ab1e165034c1a91002ab8f29e9ef9e2dab6fee7b2455bafb42037e9d2f7e533f348a147412fd72080be7c2633f5d802c91c39e6bcece3e675e59995033c55737020dad9e8b30d04b828adfb9304ad54a11a35a4f50709876ac5b118236ba76a4d7c9a291dd9607b169de1d182385691999f
		     #x1c640189d9bfe8c623833210a76c420c6f44e5d760e259916cec2ae2b156456960fd95e2747660c389562250f055049cfab7e5c3039549384a7a2aaeb1c824d3af709482a8cf9b587022a00b1f0722db50f33cb26dc20dd2245d5265df61ee2983c938c2167dcee121fc4b4479c237e728cf633ab60a8c0ecd04fce7e3baa559)

(test-rsa-pkcs1-v1.5 (integer->bytevector #x54657374 4)
		     (integer->bytevector #x4501b4d669e01b9ef2dc800aa1b06d49196f5a09fe8fbcd037323c60eaf027bfb98432be4e4a26c567ffec718bcbea977dd26812fa071c33808b4d5ebb742d9879806094b6fbeea63d25ea3141733b60e31c6912106e1b758a7fe0014f075193faa8b4622bfd5d3013f0a32190a95de61a3604711bc62945f95a6522bd4dfed0a994ef185b28c281f7b5e4c8ed41176d12d9fc1b837e6a0111d0132d08a6d6f0580de0c9eed8ed105531799482d1e466c68c23b0c222af7fc12ac279bc4ff57e7b4586d209371b38c4c1035edd418dc5f960441cb21ea2bedbfea86de0d7861e81021b650a1de51002c315f1e7c12debe4dcebf790caaa54a2f26b149cf9e77d 2048)
		     #x00b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf861075c677c81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d
		     #x010001
		     #x1a502d0eea6c7b69e21d5839101f705456ed0ef852fb47fe21071f54c5f33c8ceb066c62d727e32d26c58137329f89d3195325b795264c195d85472f7507dbd0961d2951f935a26b34f0ac24d15490e1128a9b7138915bc7dbfa8fe396357131c543ae9c98507368d9ceb08c1c6198a3eda7aea185a0e976cd42c22d00f003d9f19d96ea4c9afcbfe1441ccc802cfb0689f59d804c6a4e4f404c15174745ed6cb8bc88ef0b33ba0d2a80e35e43bc90f350052e72016e75b00d357a381c9c0d467069ca660887c987766349fcc43460b4aa516bce079edd87ba164307b752c277ed9528ad3ba0bf1877349ed3b7966a6c240110409bf4d0fade0c68fdadd847fd
		     #xec125cf37e310a2ff46263b9b2e0629d6390005ec88913d4fb71bd4dd856124498aaeba983d7ba2bd942e64d223feb7a23af4d605efeea6bd70d39afe99d35a3aa15e74a1768778093be0edd4a8d09b2def6dc9b67ff85764625c2e19236db4c401ce30a2572d3ecb4f969b7ad19c522c02d774465676e1a3776c54d6248348b
		     #xc2742abcd9897bd4b0b671f973fc82a8f84abf5705ff88dd41948623afe9dca60dc6543390767feaebeb539576ee8bfa61b5fcbca94a7cef75a09150c540fa9694dd8004ad23718c889049219369c99f4458d4afc148f6f07df87324a96d9cf7b385dd8622414a1832f9f29446f050c2d5a6407649dc41ab70e23b3dcc22c987
		     #x96a9798d250263400bb6277342881627e07cecdf91187b01b89ff47314188a7c20fb24800156d2c85d5666e8df6ceff9f9804ddfad80ff5767de56ecc029c72bf6c717df9f64daafc29acf9dc7908f9a0ad67e20e8949936ccba18d021a2c4febb04349a2b2047c4901385b6e5d0c691d118b33f81802b32ac272ef09e42fad5
		     #x554f41b0b87f68a45722b3be0cf4ab1e165034c1a91002ab8f29e9ef9e2dab6fee7b2455bafb42037e9d2f7e533f348a147412fd72080be7c2633f5d802c91c39e6bcece3e675e59995033c55737020dad9e8b30d04b828adfb9304ad54a11a35a4f50709876ac5b118236ba76a4d7c9a291dd9607b169de1d182385691999f
		     #x1c640189d9bfe8c623833210a76c420c6f44e5d760e259916cec2ae2b156456960fd95e2747660c389562250f055049cfab7e5c3039549384a7a2aaeb1c824d3af709482a8cf9b587022a00b1f0722db50f33cb26dc20dd2245d5265df61ee2983c938c2167dcee121fc4b4479c237e728cf633ab60a8c0ecd04fce7e3baa559)

(test-rsa-pkcs1-v1.5-invalid-padding
 (integer->bytevector #x6e0d507f66e16d4b7373a504c6d48692aaa541fdd59eeb5d4a2cd91f6000ce9b5734a232d6541a78729ac82152d3a30b51950a24ae379a108ed20fa4ec7542fe2281c2dd5de685564d15182f3c73e9c0135ebc993f5acd240a343d3257997582328c31be215c7349375406aa78a3ac35327226839bee2f1a4a0f8e6e06986cb33806c93e0b0c1d6cfd23f4a68c1f2a38c74b8df70f280984a840c710c52279034d04f61e313d4bcd8b3b5c58468a44565a1acb2eefc6d49044be7163e64ed84b5e7991ecba274a3a7ee4defb842a86ac4cbf2d3bfc9cf870ae025a3e2fbc775916a59579763c06eb84ad8edd1d03787e609ad446de43ebed16330ab06716fa73 2048)
 #x00b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf861075c677c81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d
 #x010001
 #x1a502d0eea6c7b69e21d5839101f705456ed0ef852fb47fe21071f54c5f33c8ceb066c62d727e32d26c58137329f89d3195325b795264c195d85472f7507dbd0961d2951f935a26b34f0ac24d15490e1128a9b7138915bc7dbfa8fe396357131c543ae9c98507368d9ceb08c1c6198a3eda7aea185a0e976cd42c22d00f003d9f19d96ea4c9afcbfe1441ccc802cfb0689f59d804c6a4e4f404c15174745ed6cb8bc88ef0b33ba0d2a80e35e43bc90f350052e72016e75b00d357a381c9c0d467069ca660887c987766349fcc43460b4aa516bce079edd87ba164307b752c277ed9528ad3ba0bf1877349ed3b7966a6c240110409bf4d0fade0c68fdadd847fd
 #xec125cf37e310a2ff46263b9b2e0629d6390005ec88913d4fb71bd4dd856124498aaeba983d7ba2bd942e64d223feb7a23af4d605efeea6bd70d39afe99d35a3aa15e74a1768778093be0edd4a8d09b2def6dc9b67ff85764625c2e19236db4c401ce30a2572d3ecb4f969b7ad19c522c02d774465676e1a3776c54d6248348b
 #xc2742abcd9897bd4b0b671f973fc82a8f84abf5705ff88dd41948623afe9dca60dc6543390767feaebeb539576ee8bfa61b5fcbca94a7cef75a09150c540fa9694dd8004ad23718c889049219369c99f4458d4afc148f6f07df87324a96d9cf7b385dd8622414a1832f9f29446f050c2d5a6407649dc41ab70e23b3dcc22c987
 #x96a9798d250263400bb6277342881627e07cecdf91187b01b89ff47314188a7c20fb24800156d2c85d5666e8df6ceff9f9804ddfad80ff5767de56ecc029c72bf6c717df9f64daafc29acf9dc7908f9a0ad67e20e8949936ccba18d021a2c4febb04349a2b2047c4901385b6e5d0c691d118b33f81802b32ac272ef09e42fad5
 #x554f41b0b87f68a45722b3be0cf4ab1e165034c1a91002ab8f29e9ef9e2dab6fee7b2455bafb42037e9d2f7e533f348a147412fd72080be7c2633f5d802c91c39e6bcece3e675e59995033c55737020dad9e8b30d04b828adfb9304ad54a11a35a4f50709876ac5b118236ba76a4d7c9a291dd9607b169de1d182385691999f
 #x1c640189d9bfe8c623833210a76c420c6f44e5d760e259916cec2ae2b156456960fd95e2747660c389562250f055049cfab7e5c3039549384a7a2aaeb1c824d3af709482a8cf9b587022a00b1f0722db50f33cb26dc20dd2245d5265df61ee2983c938c2167dcee121fc4b4479c237e728cf633ab60a8c0ecd04fce7e3baa559)

(test-end)
