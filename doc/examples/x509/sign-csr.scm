#!r6rs
(import (rnrs)
	(springkussen signature) ;; For key pair generation
	(springkussen x509))

;; Generates a default length key pair
(define rsa-key-pair
  (key-pair-factory:generate-key-pair *key-pair-factory:rsa*))

;; To make R6RS portable, we can't use SRFI-19 date :)
;; Users are free to use non-standard date library
;; The format of the date must be 'yyMMddhhmmssZ'
(define validity
  (make-x509-validity "221207102146Z" "351207102146Z"))

;; CA's issuer-dn
(define issuer-dn
  (make-x509-distinguished-names '(CN "Springkussen CA")
				 '(ST "Zuid-Holland")
				 '(C "NL")
				 '(E "ktakashi@ymail.com")))

(define serial-number 1) ;; make sure you have unique serial number :)

;; We use this as a CA cert to sign CSR
(define ca-cert
  (make-x509-self-signed-certificate rsa-key-pair serial-number issuer-dn validity))

;; Client certificate key pair.
(define ecdsa-key-pair
  (key-pair-factory:generate-key-pair *key-pair-factory:ecdsa*
    (make-ecdsa-ec-parameter *ec-parameter:sect163k1*)))

(define subject-dn
  (make-x509-distinguished-names '(CN "Springkussen")
				 '(ST "Zuid-Holland")
				 '(C "NL")
				 '(E "ktakashi@ymail.com")))

(define csr
  (x509-certificate-signing-request-builder:build
   (x509-certificate-signing-request-builder-builder
    (subject subject-dn)
    (key-pair ecdsa-key-pair))))

(let ((cert (x509-certificate-signing-request:sign csr (+ serial-number 1) validity ca-cert (key-pair-private rsa-key-pair))))
  ;; validate the signed certificate
  (x509-certificate:validate cert (list (make-x509-signature-validator ca-cert)))
  ;; show the result
  (describe-x509-certificate cert))
						      
