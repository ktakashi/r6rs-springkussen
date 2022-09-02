#!r6rs
(import (rnrs)
	(springkussen digest)
	(springkussen x509)
	(springkussen signature)
	(springkussen keystore))

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

(define keystore-file "sha1-mac.p12")

(let ((keystore (pkcs12-keystore-builder
		 (mac-descriptor (make-pkcs12-mac-descriptor *digest:sha1* 1024)))))
  (pkcs12-keystore-private-key-set! keystore "key" (key-pair-private ecdsa-key-pair) "password")
  (pkcs12-keystore-certificate-set! keystore "cert" cert)

  (when (file-exists? keystore-file) (delete-file keystore-file))
  (call-with-port (open-file-output-port keystore-file)
   (lambda (out) (write-pkcs12-keystore keystore out "password")))
  ;; Check with keytool or other Java keystore tools
  )
