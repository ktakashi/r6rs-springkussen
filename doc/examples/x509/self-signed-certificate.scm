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

;; For self signed certificate, subjectDN = issuerDN
(define subject-dn
  (make-x509-distinguished-names '(C "NL")
				 '(ST "Zuid-Holland")
				 '(CN "Springkussen")
				 '(E "ktakashi@ymail.com")))

(define serial-number 1) ;; make sure you have unique serial number :)

(let ((cert (make-x509-self-signed-certificate rsa-key-pair serial-number subject-dn validity)))
  ;; showing result
  (describe-x509-certificate cert))
