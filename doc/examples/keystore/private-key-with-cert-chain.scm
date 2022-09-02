#!r6rs
(import (rnrs)
	(springkussen x509)
	(springkussen signature)
	(springkussen keystore))


;; Generates a default length key pair
(define ca-key-pair
  (key-pair-factory:generate-key-pair *key-pair-factory:ecdsa*))

;; To make R6RS portable, we can't use SRFI-19 date :)
;; Users are free to use non-standard date library
;; The format of the date must be 'yyMMddhhmmssZ'
(define validity
  (make-x509-validity "220901102146Z" "351207102146Z"))

;; CA's issuer-dn
(define issuer-dn
  ;; It doesn't order automatically, so put it correct order manually
  (make-x509-distinguished-names '(C "NL")
				 '(ST "Zuid-Holland")
				 '(CN "Springkussen CA")
				 '(E "ktakashi@ymail.com")))

(define serial-number 1) ;; make sure you have unique serial number :)

;; We use this as a CA cert to sign CSR
(define ca-cert
  (make-x509-self-signed-certificate ca-key-pair serial-number issuer-dn validity))

;; Client certificate key pair.
(define ecdsa-key-pair
  (key-pair-factory:generate-key-pair *key-pair-factory:ecdsa*))

(define subject-dn
  (make-x509-distinguished-names '(C "NL")
				 '(ST "Zuid-Holland")
				 '(CN "Springkussen")
				 '(E "ktakashi@ymail.com")))

(define csr
  (x509-certificate-signing-request-builder:build
   (x509-certificate-signing-request-builder-builder
    (subject subject-dn)
    (key-pair ecdsa-key-pair))))

(define cert
  (x509-certificate-signing-request:sign csr (+ serial-number 1)
					 validity ca-cert
					 (key-pair-private ecdsa-key-pair)))

(define keystore-file "cert-chain.p12")
(let ((keystore (pkcs12-keystore-builder)))
  (pkcs12-keystore-private-key-set! keystore "key" (key-pair-private ecdsa-key-pair) "test")
  ;; To associate a certificate to a private key,
  ;; just use the same alias as the private key
  (pkcs12-keystore-certificate-set! keystore "key" cert)
  ;; If the ca cert is a chain certificate, just put it like this
  (pkcs12-keystore-certificate-set! keystore ca-cert)

  (when (file-exists? keystore-file) (delete-file keystore-file))
  (call-with-port (open-file-output-port keystore-file)
   (lambda (out) (write-pkcs12-keystore keystore out "password")))
  ;; Check with keytool or other Java keystore tools
  )
