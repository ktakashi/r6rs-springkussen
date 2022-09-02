#!r6rs
(import (rnrs)
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

(define self-signed-cert
  (make-x509-self-signed-certificate ecdsa-key-pair serial-number subject-dn validity))

(define keystore-file "java-trusted-cert.p12")

(let ((keystore (pkcs12-keystore-builder)))
  (pkcs12-keystore-certificate-set! keystore "cert" self-signed-cert)
  ;; Mark as Java's trusted certificate entry
  (pkcs12-keystore-add-attribute! keystore "cert" (pkcs12-entry-types certificate) *java-trusted-certificate-attribute*)
  (when (file-exists? keystore-file) (delete-file keystore-file))
  (call-with-port (open-file-output-port keystore-file)
   (lambda (out) (write-pkcs12-keystore keystore out "password")))
  ;; Check with keytool or other Java keystore tools
  )
