#!r6rs
(import (rnrs)
	(springkussen cipher symmetric)
	(springkussen digest)
	(springkussen x509)
	(springkussen signature)
	(springkussen keystore))

;; Generates a self signed certificate
(define ecdsa-key-pair
  (key-pair-factory:generate-key-pair *key-pair-factory:ecdsa*))

(define validity
  (make-x509-validity "220901102146Z" "351207102146Z"))

(define subject-dn
  (make-x509-distinguished-names '(C "NL")
				 '(ST "Zuid-Holland")
				 '(CN "Springkussen")
				 '(E "ktakashi@ymail.com")))

(define serial-number 1)

(define cert
  (make-x509-self-signed-certificate ecdsa-key-pair serial-number subject-dn validity))

(define *pbes2-des-cbc-pad/hmac-sha1*
  (make-pbes2-algorithm-identifier-provider *digest:sha1* 8 1000 8 *scheme:des*))

(define keystore-file "des-sha1.p12")
(let ((keystore (pkcs12-keystore-builder)))
  ;; To check with OpenSSL, key password and store password must be the same...
  (pkcs12-keystore-private-key-set! keystore "key" (key-pair-private ecdsa-key-pair) "password" *pbes2-des-cbc-pad/hmac-sha1*)
  (pkcs12-keystore-certificate-set! keystore "key" cert)
  
  (when (file-exists? keystore-file) (delete-file keystore-file))
  (call-with-port (open-file-output-port keystore-file)
   (lambda (out) (write-pkcs12-keystore keystore out "password")))
  ;; Check with OpenSSL
  ;; NOTE: Java doesn't support PBES2 with RC2
  )
