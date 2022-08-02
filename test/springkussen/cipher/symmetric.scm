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

(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
