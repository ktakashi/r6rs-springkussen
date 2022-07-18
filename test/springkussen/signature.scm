#!r6rs
(import (rnrs)
	(springkussen asn1)
	(springkussen signature)
	(springkussen conditions)
	(srfi :64)
	(testing))

(test-begin "Signature API")

;; descriptors
(test-assert (signer-descriptor? *signer:rsa*))
(test-equal "RSA" (signer-descriptor-name *signer:rsa*))

(test-assert (verifier-descriptor? *verifier:rsa*))
(test-equal "RSA" (verifier-descriptor-name *verifier:rsa*))

(test-assert (signer-descriptor? *signer:ecdsa*))
(test-equal "ECDSA" (signer-descriptor-name *signer:ecdsa*))

(test-assert (verifier-descriptor? *verifier:ecdsa*))
(test-equal "ECDSA" (verifier-descriptor-name *verifier:ecdsa*))

;; key
(define (test-key-operation operation key)
  (test-assert (asymmetric-key-operation? operation))
  (test-assert (asymmetric-key? (asymmetric-key:import-key operation key)))
  (test-equal key
	      (asymmetric-key:export-key operation
	       (asymmetric-key:import-key operation key))))

(test-key-operation *public-key-operation:rsa*
		    (hex-string->bytevector "30819F300D06092A864886F70D010101050003818D0030818902818100AA18ABA43B50DEEF38598FAF87D2AB634E4571C130A9BCA7B878267414FAAB8B471BD8965F5C9FC3818485EAF529C26246F3055064A8DE19C8C338BE5496CBAEB059DC0B358143B44A35449EB264113121A455BD7FDE3FAC919E94B56FB9BB4F651CDB23EAD439D6CD523EB08191E75B35FD13A7419B3090F24787BD4F4E19670203010001"))

(test-key-operation *private-key-operation:rsa*
		    (hex-string->bytevector "308204A40201000282010100CB0605EF570A4A8DF1CA2EFFD12ECDD5B9450A6057E1E673D205DFFB3C817E89AEAA1C2B7A465BBC8D52458411ADB37BE340EEBA0B8D61D7BEB5D40ECA59CBEFA784235405E39FCC19C0216C3DE15B11FDDEC2DFFB4572510DB6583EFD14F667058FD6E18E39E56FD9F36E049354AE6CA9A8CD057F58E333D04623BCDFA6EB6775A6CBAC7BDB969F42702D0FFBD351E7924164B2AF60B963C6A6F99C2171D5CCF9F5B060E7DDDD914BEA94E7F2D499C96A3FE49F31F992DE3EB2AF3610D259C5069CF0DA842FBFB8F88FED2D078C4372395BE5F33D22C431CDF0809B6C85DD36AB68CDA7EE29179265CBB1456975E3E7E65A1154CB2088B0586DB0228AE4F4AD020301000102820101008D31912B14B3798A221FE473D0FCE5F5BF357EB3E62A9AE4EDA95C4E13945376595CC0DE93D91EAF90F1289B62D814BD121CF469BAE306AACE5D122F7F16D837C19EAA1B23455CBACB25CD98C3A85877B8C115724403D62EFC8455F6E8778DADB43686D0B2E31CE79F0226FF539F4EF70F3EEFE6E4DBE297043FE356D58BF6A5ED427184D0D253A333588E146B970063ADE6CAB8A9A4637C23D4895EF4C1305B9CC08E62B21258604437811800007FA26926E283C8A5E94B32B7C4B32799E898224CCF5CD4E13409DB6A4FD8671A14F4B4BC3FF3F83EBEC610AA0CFDABBA7E7FBAA5C0E1812C863E765ACEAC0190D504C09D681FFAD83AA9A06E8F21D0FD0B5902818100F526B447E9FB8E84D931236B793A0BA31A20A5ED45731D126E07432350318EEA8573F62813610A123C7CC2075CCF2C27BE0A6AC5C871E414D3831E9DCFB64E3971309A3ACD157395BEFA13D43573175A7E5DA5933907962CF20DBDF45DAE7D655CB200BCE52396774FFEA82FA78F25493A465E1F973E853683242388BBEFA25B02818100D4020EF8CE176901831E4B96C600BF0BCE4F004F75C8EA6BD6AEAB46669979CD2F12546AC584CCA6D5B0AD989B5D945927F6023576D2293F814C92ADD22960CEA481250A911C61B60F9AD740E636FC4FEEEE740C420E0AC66484A02AD581308E9B99567151F01B982D8D787BA1F2D6FCD275FD294D0B720966F92FF1E3B96397028181009C01024E953690EE376C8EB6B0D160606D9B031C27CAE66039068411EFD169BA122CC623A0996B1849C7B68D8AE1079F4ECF403D169E6B5F596E224898CAD1A2BA460C8F88BCB2EE4336CEF18705F38191D2B43028E58C0A940A6CAC1A059524B0C551B4E3382F6343D3B1618A068CDAB9ABD7EFD08667AD55ECE473F9ECB7EB028180577409ED04468FE039D0136A3C7F2E4F9668EC3DDADE6824D7C7F18AF6E3B464B9581C4E76EFD2E3B71E4C5DB9291EFAB00B40DA010BAC4C2FF000498779DE1F1FA8CE38CFA71F7F546C91028A74801C10F978115E662077BA1B235EC7F7A4AA0EF16FC10B05BABC497E24070BC4FA7E0BEAF3E5478CC31BB1C874C899216E3D028180150DA819C4139C2C29C5AFC309426C02C2DBD7BD5308E494FEF9F5D51BB87E8ADB0A7AE5B644E3992F8D4DC96C7068C2D445763618CB5E192047A609A54031F1762FDA2F5D1063D30B75FF1A75A040AA1A0312BE12A0A8EEF296A0C3A96A9BAE577804725A4C6A16A0196DBD8ADDB598DF1F6A653EA8B9B2EB08318328195745"))

(test-key-operation *public-key-operation:ecdsa*
		    (hex-string->bytevector "304e301006072a8648ce3d020106052b81040021033a0004eada93be10b2449e1e8bb58305d52008013c57107c1a20a317a6cba7eca672340c03d1d2e09663286691df55069fa25490c9dd9f9c0bb2b5"))

(test-key-operation *private-key-operation:ecdsa*
		    (hex-string->bytevector "3074020101042010055850250963DBF08BCCE321CB2CA04837F984254F5C667339243D94D84980A00706052B8104000AA14403420004ACC1948DB1DC11FEC693D81538E95676A49A19CD18844E4704FAA1A27881506F0C4F1E404FB9B1B6ECA7424C9D31E39C887CAFBF253481FF35516F6E75E7F69C"))

(define (test-self-check desc kp-op signer verifier key-param sig-param)
  (define kp (key-pair-factory:generate-key-pair kp-op key-param))
  (define (sign msg)
    (signer:sign-message (make-signer signer sig-param)
			 (key-pair-private kp) msg))
  (define (verify msg S)
    (verifier:verify-signature (make-verifier verifier sig-param)
			       (key-pair-public kp) msg S))
  (define (check msg)
    (let ((r (verify msg (sign msg))))
      (test-assert (string-append desc "(" (utf8->string msg) ")") r)))
  (check #vu8())
  (check #vu8(1 2 3 4 5))
  (check (string->utf8 "Hello Springkussen")))

(test-self-check "RSA EMSA v1.5"
		 *key-pair-factory:rsa* *signer:rsa* *verifier:rsa*
		 (make-key-size-key-parameter 2048)
		 (make-signature-parameter
		  (make-rsa-signature-encode-parameter pkcs1-emsa-v1.5-encode)
		  (make-rsa-signature-verify-parameter pkcs1-emsa-v1.5-verify)))
(test-self-check "RSA EMSA PSS"
		 *key-pair-factory:rsa* *signer:rsa* *verifier:rsa*
		 (make-key-size-key-parameter 2048)
		 (make-signature-parameter
		  (make-rsa-signature-encode-parameter pkcs1-emsa-pss-encode)
		  (make-rsa-signature-verify-parameter pkcs1-emsa-pss-verify)))

(define (test-ecdsa-self-check ec-param)
  (test-self-check "ECDSA"
		   *key-pair-factory:ecdsa* *signer:ecdsa* *verifier:ecdsa*
		   (make-ecdsa-ec-parameter ec-param)
		   (make-signature-parameter))
  (test-self-check "ECDSA (der encoded)"
		   *key-pair-factory:ecdsa* *signer:ecdsa* *verifier:ecdsa*
		   (make-ecdsa-ec-parameter ec-param)
		   (make-ecdsa-encode-parameter
		    (ecdsa-signature-encode-type der))))

;; Doing some of them, more comprehensive tests are in ecdsa.scm
(for-each test-ecdsa-self-check
	  (list *ec-parameter:p192*
		*ec-parameter:p224*
		*ec-parameter:p256*
		*ec-parameter:secp192r1*
		*ec-parameter:secp224r1*
		*ec-parameter:secp256r1*))

(for-each (lambda (ep) (test-assert (ec-parameter? ep)))
	  (list *ec-parameter:p192*
		*ec-parameter:p224*
		*ec-parameter:p256*
		*ec-parameter:p384*
		*ec-parameter:p521*
		*ec-parameter:k163*
		*ec-parameter:k233*
		*ec-parameter:k283*
		*ec-parameter:k409*
		*ec-parameter:k571*
		*ec-parameter:b163*
		*ec-parameter:b233*
		*ec-parameter:b283*
		*ec-parameter:b409*
		*ec-parameter:b571*
		*ec-parameter:secp192r1*
		*ec-parameter:secp224r1*
		*ec-parameter:secp256r1*
		*ec-parameter:secp384r1*
		*ec-parameter:secp521r1*
		*ec-parameter:sect163k1*
		*ec-parameter:sect233k1*
		*ec-parameter:sect283k1*
		*ec-parameter:sect409k1*
		*ec-parameter:sect571k1*
		*ec-parameter:sect163r2*
		*ec-parameter:sect233r1*
		*ec-parameter:sect283r1*
		*ec-parameter:sect409r1*
		*ec-parameter:sect571r1*
		*ec-parameter:secp192k1*
		*ec-parameter:secp224k1*
		*ec-parameter:secp256k1*
		*ec-parameter:sect163r1*
		*ec-parameter:sect239k1*
		*ec-parameter:sect113r1*))

(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
