#!r6rs
(import (rnrs)
	(springkussen keystore)
	(springkussen conditions)
	(springkussen signature)
	(springkussen cipher symmetric)
	(springkussen x509)
	(srfi :64))

(test-begin "Keystore")

;; This file is generated by KeyStore Explorer 5.5.1
;; which doesn't support some of our entry types, e.g. CRL
(define pfx.p12 (string-append (cadr (command-line)) "/pfx.p12"))

(define (read-p12-keystore file password)
  (call-with-port (open-file-input-port file)
   (lambda (in) (read-pkcs12-keystore in password))))

(define ca-key-pair
  (key-pair-factory:generate-key-pair *key-pair-factory:ecdsa*))
(define update (make-x509-time "220830102146Z"))
(define crl-builder
  (x509-certificate-revocation-list-builder-builder
   (issuer (make-x509-distinguished-names '(C "NL")
					  '(O "Springkussen")
					  '(CN "Springkussen")))
   (this-update update)
   (next-update (make-x509-time "351207102146Z"))
   (revoked-certificates
    (list (make-x509-revoked-certificate 100 update)))))
(define crl (x509-certificate-revocation-list-builder:build
	     crl-builder (key-pair-private ca-key-pair)))

;; Enums
(test-equal '(private-key certificate crl secret-key safe-contents unknown)
	    (enum-set->list (enum-set-universe (pkcs12-entry-types))))
(test-equal 'private-key (pkcs12-entry-type private-key))

(test-assert (pkcs12-keystore? (pkcs12-keystore-builder)))
(test-error springkussen-condition?
	    (read-p12-keystore pfx.p12 "wrong password"))

(let ((ks (read-p12-keystore pfx.p12 "storepass")))
  (define (check-entry-types eset alias)
    (define ctr (enum-set-constructor (pkcs12-entry-types)))
    (test-assert `(,(string-append alias " contains ") ,eset)
     (enum-set=? (pkcs12-keystore-alias-entries ks alias) (ctr eset))))
  (test-assert (pkcs12-keystore? ks))
  (test-assert (pkcs12-keystore-contains? ks "aeskey"))
  (test-assert (pkcs12-keystore-contains? ks "springkussen ec"))
  (test-assert (pkcs12-keystore-contains? ks "springkussen rsa"))
  (test-assert (pkcs12-keystore-contains? ks "springkussen chain"))
  (test-assert (pkcs12-keystore-contains? ks "ca-cert"))
  (test-assert (pkcs12-keystore-contains? ks "google.com"))

  (check-entry-types '(private-key certificate) "springkussen ec")
  (check-entry-types '(private-key certificate) "springkussen rsa")
  (check-entry-types '(private-key certificate) "springkussen chain")

  (test-assert (not (pkcs12-keystore-contains? ks "not exist")))
  
  (test-assert (not (pkcs12-keystore-private-key-ref ks "not exist")))
  (test-assert (not (pkcs12-keystore-private-key-ref ks "aeskey")))
  (test-assert (not (pkcs12-keystore-private-key-ref ks "not exist" "pass")))
  (test-assert (not (pkcs12-keystore-private-key-ref ks "aeskey" "pass")))

  (test-assert (not (pkcs12-keystore-certificate-ref ks "not exist")))
  (test-assert (not (pkcs12-keystore-certificate-ref ks "aeskey")))

  (test-assert (not (pkcs12-keystore-certificate-revocation-list-ref
		     ks "not exist")))
  (test-assert (not (pkcs12-keystore-certificate-revocation-list-ref
		     ks "aeskey")))
  (test-assert (not (pkcs12-keystore-secret-key-ref ks "not exist")))
  (test-assert (not (pkcs12-keystore-secret-key-ref ks "not exist" "pass")))
  (test-assert (not (pkcs12-keystore-secret-key-ref ks "springkussen ec")))
  (test-assert (not (pkcs12-keystore-secret-key-ref
		     ks "springkussen ec" "pass")))

  (test-assert (ecdsa-private-key?
		(pkcs12-keystore-private-key-ref ks "springkussen ec" "test")))
  (test-error springkussen-condition?
	      (pkcs12-keystore-private-key-ref ks "springkussen ec"))
  (test-assert (rsa-private-key?
		(pkcs12-keystore-private-key-ref ks "springkussen rsa" "test")))
  (test-assert (symmetric-key?
		(pkcs12-keystore-secret-key-ref ks "aeskey" "test")))
  (test-error springkussen-condition?
	      (pkcs12-keystore-secret-key-ref ks "aeskey"))
  (test-assert (x509-certificate?
		(pkcs12-keystore-certificate-ref ks "ca-cert")))
  (test-assert (x509-certificate?
		(pkcs12-keystore-certificate-ref ks "google.com")))

  (let ((ks2 (pkcs12-keystore-builder)))
    (define (copy-entries src dest)
      (define (copy-entry alias)
	(do ((types (enum-set->list (pkcs12-keystore-alias-entries src alias))
		    (cdr types)))
	    ((null? types))
	  (case (car types)
	    ((private-key)
	     (pkcs12-keystore-private-key-set! dest alias
	       (pkcs12-keystore-private-key-ref src alias "test") "test"))
	    ((certificate)
	     (pkcs12-keystore-certificate-set! dest alias
	       (pkcs12-keystore-certificate-ref src alias)))
	    ((secret-key)
	     (pkcs12-keystore-secret-key-set! dest alias
	       (pkcs12-keystore-secret-key-ref src alias "test") "test")))))
      (let ((aliases (pkcs12-keystore-all-aliases src)))
	(for-each copy-entry aliases)))

    (copy-entries ks ks2)
    
    (pkcs12-keystore-private-key-set! ks2 "ec nopass"
     (pkcs12-keystore-private-key-ref ks "springkussen ec" "test"))
    (pkcs12-keystore-secret-key-set! ks2 "sk nopass"
     (pkcs12-keystore-secret-key-ref ks "aeskey" "test"))
    (pkcs12-keystore-certificate-revocation-list-set! ks2 "crl" crl)
    (pkcs12-keystore-certificate-revocation-list-set! ks2 "crl2" crl)

    (pkcs12-keystore-private-key-delete! ks2 "springkussen ec")
    (pkcs12-keystore-delete-entry! ks2 "springkussen chain"
				   (pkcs12-entry-types private-key certificate))
    (pkcs12-keystore-certificate-delete! ks2 "ca-cert")
    (pkcs12-keystore-secret-key-delete! ks2 "aeskey")
    (pkcs12-keystore-certificate-revocation-list-delete! ks2 "crl2")

    (let ((ks2 (bytevector->pkcs12-keystore
		(pkcs12-keystore->bytevector ks2 "pass2")
		"pass2")))
      (test-assert (not (pkcs12-keystore-contains? ks2 "aeskey")))
      (test-assert (not (pkcs12-keystore-contains? ks2 "springkussen chain")))
      ;; we have certificate entries for these two
      (test-assert (pkcs12-keystore-contains? ks2 "springkussen ec"))
      (test-assert (pkcs12-keystore-contains? ks2 "springkussen rsa"))
      ;; Chain stays, we consider it as a different entry
      (test-assert (pkcs12-keystore-contains? ks2
      		    (x509-distinguished-names->string
      		     (apply make-x509-distinguished-names
      			    (x509-certificate:issuer
      			     (pkcs12-keystore-certificate-ref
      			      ks "springkussen chain")))
      		     *x509:rfc5280-names*)))
      (test-assert (ecdsa-private-key?
		    (pkcs12-keystore-private-key-ref ks2 "ec nopass")))
      (test-assert (ecdsa-private-key?
		    (pkcs12-keystore-private-key-ref ks2 "ec nopass" "ignore")))
      (test-assert (symmetric-key?
		    (pkcs12-keystore-secret-key-ref ks2 "sk nopass")))
      (test-assert (symmetric-key?
		    (pkcs12-keystore-secret-key-ref ks2 "sk nopass" "ignore")))
      (test-assert (x509-certificate-revocation-list?
		    (pkcs12-keystore-certificate-revocation-list-ref
		     ks2 "crl"))))
  ))


(test-end)
(exit (test-runner-fail-count (test-runner-current)))
	