#!r6rs
(import (rnrs)
	(springkussen math modular)
	(srfi :64)
	(testing))

(test-begin "Moddular arighmetic")

(let ((ps
       '("c6c93915786185fa7ee88f1983cc8d238cd6c5f7a36416c8be317c3df475277784ae1b87b263b88a84d5bacaf63798474ffe490fa412cb437abe5908efbe41b1"
	 "f2d6323e96c9ad655ab520dccbc5bdf3312dcf4e32858650caa21d7e8c7ed6d13d8bbe166e0ac7cb787ef38bec6c55529f3f93b0d7c9e5ceb5188571699619bf"
	 "e50fce1d57633704798f7b2465ddccebf6e5c9f22a8e3017a39f8de7cb3b78285003dca54bf9c7a2c478add7cfd7cf678b831be1db331f2f3961435c6937a545"
	 "a9782bf45cdb460875a56c89b580df3f959f33e07ea43ec166241c5add827303815ab0131b7e98430038aed9e136b83e1a82d099bb40a26ac9497ef3abb58dfd"
	 "d265038c4fee2f3f87c8a2e15c1fa67dfac4ad5eb78bec468d9df27ffe3224581a2a189f87946a012a228f579abfb0d183e99cd831341af9b750b4582236e15d"
	 "ca911176fce31e4332ec9ada6fa268f6ea1a9a71c81599a77797d74d5c7c48491fafce22428c516d7318c36907aa76df89e92be5ab66b42b25be777640ecc76d"
	 "eb97f1e80a81d9b725dd5708fe7d65ab5339d7a339c703ee73de339fb0f10a4d76bd827536b9f6da49507ee12ca37b8157f8103f3d12a9eb9468576d9b2ef59f"))
      (qs
       '("bc5e04097e88241c2e9f145a829c158bacb17756b0c6aba175318c4b0b799067a83509dc45fb34c82aa7d3caacc80f1d0013c9bdd24bd52f31f04edfa169ef75"
	 "da554d942ebe105e7a60070bfcaf3953f29ecfd6493aac69c6427a00be66c978515e7222180cc84606bcf7348c8aba0f9b05870cf2ab1c3669199c4316d40669"
	 "ceb5591d98f1e1bfe3095f21a7e7c47d18bfcfbb8e0a1971a13941bd4cc2c861c2ef4b85cdf52b6aaeeb20264456b3c3c2a7f6a52b21eb91276acb3caa3603d1"
	 "d47c206d19142ad870648eb09ca183cf4875f8009d91fcc0e085ac65455caf17ee5e91f2ccb564a88a8d13100faf1c95c6481c1b2e3fb6483f1bcdb2894356ad"
	 "cc36f153789677c45232afdaed78f2a20658f53fcbaa0626f64d0fa29a6f70516420999fee96dca6d232c644b09d1e27cdc0215fcbc4c36a5c493f2e1fed7bb1"
	 "e63821b08b4bcc12e80a3e019f4f424c20aa72b426fc912bb2157569f9ee4422f970bbc4bf75ac05e77e48d436ce980e0646c2ba3eafb9e98aff77e19b59257f"
	 "d8e26d53f31a647889ce845e892b076e578f0a68565005d5d23ed8a4ff8370cbb12cb41854badfe17053db1a94e754ea241ede1d879bff36b75f5fa96eb64927")))
  (for-each (lambda (p q)
	      (let* ((p (string->number p 16))
		     (q (string->number q 16))
		     (phi (* (- p 1) (- q 1))))
		(test-assert "mod-inverse" (mod-inverse #x10001 phi)))) ps qs)

  (test-equal "mod-inverse (recursion)"
	      #xa3a790f0b7d2bea3a81dc676032cf99c23c28bee
	      (mod-inverse #x1a1eb1e6b8f115eee3dc1334afc7de2f7efbd568
			   #xde09f1902cf484f232fee5d27262372d1c6072d7))

  (test-equal "mod-inverse (32bit long environment)"
	      84793287459004005994083570264676611930995373170935977255695558296701128546491
	      (mod-inverse
	       59791678501913488631701617161572303141620876383029885416585973023996318696896
	       115792089210356248762697446949407573530086143415290314195533631308867097853951)
	      )
  )

(test-equal "3 ^  5 mod 10" 3 (mod-expt 3  5 10))
(test-equal "3 ^ -5 mod 10" 7 (mod-expt 3 -5 10))
(test-equal "3 ^ -3 mod 10" 3 (mod-expt 3 -3 10))

(test-equal "bignums(1)"
	    144823644014482364401448236440
	    (mod-expt 123456789012345678901234567890
		      987654321098765432109876543210987654
		      147258369014725836901472583690))

(test-equal "bignums(4096)"
	    #x440de3080bd660cb54783479497fdbf1e107cf52ea957f95517773e5d003636e2815ad1cae60b1ae7760a172a2ae4d486af54f80d6e296227e074ed636460ff15b505fa2ec3fa2f63c2a7ce5eb8345b31fbb904a05285cfbe3debe7d8bf4b6b9e42e02b1f1b78e9b4a46fb82f5d30658cc94ac13c36e0f781e65e58c9aed719672869734ebefbe9d5d9c215223560aa2ba0102c876da1dc24280e53cd54878284c8c5d40015f83324984691a7780bae0019d292fc8145c989c26eafef3efcc800d85fd7278956aad02f73e0b62d8e90bef329442a8efe07fbd9f5036ee7e4d94df159ce5215c616e088409540684a1fefacced9eb14b87bb6c5396ffd455fb08c861bc7c358540502d584cec1e8289980002c6b354012129ff5b48d9dc6a3c98f5f90454aa729d58ad6764264c610eb3ff7a2ba406fbec534c1ae2c874a92fc22a6e26dfde3c8856292f1b4bcb9b29a61e748baa4265abd65f2a1b1f8b244b3067b5f3d8c14be54dbd76637d0b5aca7f7ca6ffe3a1e989012d281737f45b9dc94fe4ffa6f0cebe3757366efa69f5b319a6623832adcca3e85a3fcd730282a0125dd1ccdff95710ac34d14f86ad2f718c48752693ea4295c9f70f6111ed1833ac5dc61d3c061d0b7906d3e7612352fbf3d3827412f8b513cc27b0648c7ceb5a3ee2e72d6a55ddad2d55fa2a5d58248902760a65b9c01b85a43c9ab4aabc6d2141
	    (mod-expt #x2d2875f005db8c7ef05939e2c4a0e004d0484c2695399d31451732a7d3ec5237c916e0f79480bb8cd66dc3a51d99f7b21d473123e264a58ff7cdf434f99bdf363d22bc2adb35e3c227f071e55916078c0c2fc05badb4868772e079b812fff3360bf2492bc39a90eb01a719532a197901426ed2af7a4a4d65ff902ce0cc4902b21fd981d6e2c97c73586ee6df462ef14d274c414cf5a48a20fcb0a5a4e73a028b0f8a2f671620e3fda15a600cfb12d41bf0957a88cd812675e3949f34ef49382905ce89d10ae321724463913b66ea5bd20af66ddf74a3600bfa9db9ff4b45413d47a9f2a9a2f9539f6a747183bfc499e5aab66c853c0481ad45ca5663b285895c0f598b8ddcad057be03d28f63bc6d20426d542ff43da2158ddc1117ffc721e6917f36d2696dc1e31a53cad6f7d8e114c783f1d52ddf2bd1e50f3a4cbc0740d3658848a8b8207d154d3afff34d45cf8e8a8a448dd491b93bf5da47d0f14d55aafdef63f18d6255361349a78d5f5dc0b171eaed74b5c33ab79ef403d6fb7b68ff93ffaf68f288b5d842958ebea3303042e22cf2f999d7a631a023f7ec2ad29bc0450080f1d72af5d7a24b5ae6c88822e5ff442f2a42d18ebc99ffc9a06925f5380216c2d7ad249f1305a321fb4229f2eb2cb590bb8e93b674c1296e5438567a89ee264ee7c5d034c0a7137ed14663d572b1583e1129f386e0428f4d42c1bc9e311
		      #x10001
		      #xd2de09e51c3f01ff3fd33e378843f0201bac1a76d758ac3d41663b308c28e59bc6b3a1323de9a37a720c54e7d16f3bcf926fedd0e5405e595d71537728c837ed1c0d857defc7a7dd5698c6b43af0d149d96fcdb847f156d738f665f8e6437e0558e3e03a048791ee6d4bf390a6df4775bacc6b4b38c707cb4462a68ccc652d74f2838ac27cce3ecc322a31e87d5043ed8d4b9dbe92597b5968e468a7506ff4208161b1688689e5be65864a847198904b16c5738e66ba3b1deeca681b427cef473a1f8c6c4941659acd040f8593362b17293688f1d63574be41a8b6c8d8c688e231a2b0852ec458f3cc7cc306dd0a4358ee82671f955d12dfde93b6337d7f0a4e2e7722d70f5ed4d5680d710e5306bff6adb7c52aed8ac89b25aec9d125398f96f9a8a59465c46c9afddcb0c3f7f0199ee234bee840213fbe19542b7a3bf54b2e84985d9a0352e9ca7b826df0f93253a1acd46e02b6339d4eb91e0792ea96d6192b8067d11667f4f1130cba6a2fb01f180d5b606c868c7f4d987d06b104db44042727243261b8cee3efdad884e36b0adb8e6a8240a794c219b021436de68ed321548306413029ace2364f679ddfd87e94b81caa7a05136dbd9585126e0af62f93b87bf6b1c54d69c8da6bd130582d01cc3a68691bbffe9c205228dfb63a87aaa9f5c378331160e93ad3f449ff0fd15fd29b9237eabdc175dd49addb5f658a0881))


(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
