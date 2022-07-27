#!r6rs
(import (rnrs)
	(springkussen asn1)
	(springkussen misc base64)
	(springkussen signature)
	(springkussen x509)
	(srfi :64)
	(testing))

(test-begin "X509")

;; test data from
;; https://fm4dd.com/openssl/certexamples.shtm
;; RSA 1024 and ECDSA sect571r1
(define (b64-string->certificate s)
  (bytevector->x509-certificate (base64-decode (string->utf8 s))))

(define root-cert
  (b64-string->certificate
   (string-append
    "MIIDvDCCAyWgAwIBAgIJAMbHBAm8IlugMA0GCSqGSIb3DQEBBQUAMIGbMQswCQYD"
    "VQQGEwJKUDEOMAwGA1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNV"
    "BAoTCEZyYW5rNEREMRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMT"
    "D0ZyYW5rNEREIFdlYiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRk"
    "ZC5jb20wHhcNMDcxMjA3MTAyMTQ2WhcNMTcxMjA0MTAyMTQ2WjCBmzELMAkGA1UE"
    "BhMCSlAxDjAMBgNVBAgTBVRva3lvMRAwDgYDVQQHEwdDaHVvLWt1MREwDwYDVQQK"
    "EwhGcmFuazRERDEYMBYGA1UECxMPV2ViQ2VydCBTdXBwb3J0MRgwFgYDVQQDEw9G"
    "cmFuazRERCBXZWIgQ0ExIzAhBgkqhkiG9w0BCQEWFHN1cHBvcnRAZnJhbms0ZGQu"
    "Y29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7r7yPJdXmDL2/+L2iogxQ"
    "rLML+10EwAY9lJRCHGPqSJ8if7teqnXgFr6MAEiCwTcLvk4h1UxLrDXmxooegNg1"
    "zx/OODbcc++SfFCGmflwj/wjLpYRwPgux7/QIgrUqzsj2HtdRFd+WPVD4AOtY9gn"
    "xjNXFpVe1zmgAm/UFLdMewIDAQABo4IBBDCCAQAwHQYDVR0OBBYEFGLze+0G1LHV"
    "nH9I5e/FyRVh/dkRMIHQBgNVHSMEgcgwgcWAFGLze+0G1LHVnH9I5e/FyRVh/dkR"
    "oYGhpIGeMIGbMQswCQYDVQQGEwJKUDEOMAwGA1UECBMFVG9reW8xEDAOBgNVBAcT"
    "B0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNEREMRgwFgYDVQQLEw9XZWJDZXJ0IFN1"
    "cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdlYiBDQTEjMCEGCSqGSIb3DQEJARYU"
    "c3VwcG9ydEBmcmFuazRkZC5jb22CCQDGxwQJvCJboDAMBgNVHRMEBTADAQH/MA0G"
    "CSqGSIb3DQEBBQUAA4GBALosLpHduFOY30wKS2WQ32RzRgh0ZWNlLXWHkQYmzTHN"
    "okwYLy0wGfIqzD1ovLMjDuPMC3MBmQPg8zhd+BY2sgRhgdEBmYWTiw71eZLLmI/e"
    "dQbu1z6rOXJb8EegubJNkYTcuxsKLijIfJDnK2noqPt03puJEsBxosN14XPEhIEO")))

;; we use this as a CA form CSR so ca-cert :)
(define ca-cert
  (b64-string->certificate
   (string-append
    "MIICVjCCAb8CAg37MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG"
    "A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE"
    "MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl"
    "YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw"
    "ODIyMDUyNzIzWhcNMTcwODIxMDUyNzIzWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE"
    "CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs"
    "ZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMYBBrx5PlP0WNI/ZdzD"
    "+6Pktmurn+F2kQYbtc7XQh8/LTBvCo+P6iZoLEmUA9e7EXLRxgU1CVqeAi7QcAn9"
    "MwBlc8ksFJHB0rtf9pmf8Oza9E0Bynlq/4/Kb1x+d+AyhL7oK9tQwB24uHOueHi1"
    "C/iVv8CSWKiYe6hzN1txYe8rAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAASPdjigJ"
    "kXCqKWpnZ/Oc75EUcMi6HztaW8abUMlYXPIgkV2F7YanHOB7K4f7OOLjiz8DTPFf"
    "jC9UeuErhaA/zzWi8ewMTFZW/WshOrm3fNvcMrMLKtH534JKvcdMg6qIdjTFINIr"
    "evnAhf0cwULaebn+lMs8Pdl7y37+sfluVok=")))

(test-assert "X509 certificate" (x509-certificate? ca-cert))
(test-assert "Public key" (public-key? (x509-certificate:public-key ca-cert)))
(test-assert "RSA public key"
	     (rsa-public-key? (x509-certificate:public-key ca-cert)))
(test-assert "IssuerDN" (list? (x509-certificate:issuer ca-cert)))
(test-assert "SubjectDN" (list? (x509-certificate:subject ca-cert)))
(test-assert "Signature" (bytevector? (x509-certificate:signature ca-cert)))

(test-assert "Certificate validate"
	     (x509-certificate:validate ca-cert
	      (list (make-x509-signature-validator root-cert))))

(define (import-b64-private-key op s)
  (asymmetric-key:import-key op (base64-decode (string->utf8 s))))
(define ca-priv-key
  (import-b64-private-key *private-key-operation:rsa*
   (string-append
    "MIICWwIBAAKBgQDGAQa8eT5T9FjSP2Xcw/uj5LZrq5/hdpEGG7XO10IfPy0wbwqP"
    "j+omaCxJlAPXuxFy0cYFNQlangIu0HAJ/TMAZXPJLBSRwdK7X/aZn/Ds2vRNAcp5"
    "av+Pym9cfnfgMoS+6CvbUMAduLhzrnh4tQv4lb/AkliomHuoczdbcWHvKwIDAQAB"
    "AoGAXzxrIwgmBHeIqUe5FOBnDsOZQlyAQA+pXYjCf8Rll2XptFwUdkzAUMzWUGWT"
    "G5ZspA9l8Wc7IozRe/bhjMxuVK5yZhPDKbjqRdWICA95Jd7fxlIirHOVMQRdzI7x"
    "NKqMNQN05MLJfsEHUYtOLhZE+tfhJTJnnmB7TMwnJgc4O5ECQQD8oOJ45tyr46zc"
    "OAt6ao7PefVLiW5Qu+PxfoHmZmDV2UQqeM5XtZg4O97VBSugOs3+quIdAC6LotYl"
    "/6N+E4y3AkEAyKWD2JNCrAgtjk2bfF1HYt24tq8+q7x2ek3/cUhqwInkrZqOFoke"
    "x3+yBB879TuUOadvBXndgMHHcJQKSAJlLQJAXRuGnHyptAhTe06EnHeNbtZKG67p"
    "I4Q8PJMdmSb+ZZKP1v9zPUxGb+NQ+z3OmF1T8ppUf8/DV9+KAbM4NI1L/QJAdGBs"
    "BKYFObrUkYE5+fwwd4uao3sponqBTZcH3jDemiZg2MCYQUHu9E+AdRuYrziLVJVk"
    "s4xniVLb1tRG0lVxUQJASfjdGT81HDJSzTseigrM+JnBKPPrzpeEp0RbTP52Lm23"
    "YARjLCwmPMMdAwYZsvqeTuHEDQcOHxLHWuyN/zgP2A==")))

(define ec-cert
  (b64-string->certificate
   (string-append
    "MIICXjCCAccCAg4GMA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG"
    "A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE"
    "MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl"
    "YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw"
    "OTI3MTMwMDE0WhcNMTcwOTI2MTMwMDE0WjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE"
    "CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs"
    "ZS5jb20wgacwEAYHKoZIzj0CAQYFK4EEACcDgZIABAIZ0Rc0Y3jsqPqqptRz3tiS"
    "AuvTHA9vUigM2gUjM6YkTKofP7RRls4dqt6aM7/1eLbFg4Jdh9DXS4zU1EFeiZQZ"
    "+drSQYAmAgAtTzpmtmUoy+miwtiSBomu3CSUe6YrVvWb+Oirmvw2x3BCTJW2Xjhy"
    "5y6tDPVRRyhg0nh5wm/UxZv4jo7AZuJV8ztZKwCEADANBgkqhkiG9w0BAQUFAAOB"
    "gQBlaOF5O4RyvDQ1qCAuM6oXjmL3kCA3Kp7VfytDYaxbaJVhC8PnE0A8VPX2ypn9"
    "aQR4yq98e2umPsrSL7gPddoga+OvatusG9GnIviWGSzazQBQTTQdESJxrPdDXE0E"
    "YF5PPxAO+0yKGqkl8PepvymXBrMAeszlHaRFXeRojXVALw==")))
(test-assert "ECDSA public key"
	     (ecdsa-public-key? (x509-certificate:public-key ec-cert)))
(test-assert (x509-certificate:validate ec-cert
	      (list (make-x509-signature-validator root-cert))))

(define csr-string
  (string-append
   "MIIC4TCCAckCAQAwgYYxCzAJBgNVBAYTAk5MMRUwEwYDVQQIDAxadWlkLWhvbGxh"
   "bmQxDzANBgNVBAcMBkxlaWRlbjEVMBMGA1UECgwMU3ByaW5na3Vzc2VuMRUwEwYD"
   "VQQDDAxTcHJpbmdrdXNzZW4xITAfBgkqhkiG9w0BCQEWEmt0YWthc2hpQHltYWls"
   "LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL5NkYRz38upOH2s"
   "I0y2v6eK6opmMiZdRTSaP5eBHZyQVKzjz5dbVu+8h7tcxbWT70COqyg8Z7SoNwuX"
   "0epUJX2HRD4AEEPuhRhcWtCCBbyC6Owlt8X5x+Vh5hU2pkfo1lQCUK0v9guqhhxz"
   "wUwyo4/MU+/GIGZFGoidbyCWOO1JqSebcI5bWO2dw47VfHe7hf5bvn7J1GA36IKO"
   "+m8w11OUNTSSK1WHlstl7caA92HJfwQafaFGnxnmDalSR7bvYfDLXgMiWFE1/rdp"
   "qLpSvLr32fxCR4gJHn3rtzEZ2Go7k4vYT3B2dVGaq2QzqqP5vKLQAuaMyFDrNcO4"
   "oH1IiHcCAwEAAaAVMBMGCSqGSIb3DQEJBzEGDAR0ZXN0MA0GCSqGSIb3DQEBCwUA"
   "A4IBAQC3LLilZYGxWsvzJF0s56e5keBzcpMex8cYif4KP/itO44TcyFXGlxKFd76"
   "5EVZXCooOUoUqswrMuqXAqaKCPUtJw4r+LF0o6L1jahedaqCkrrEzdQ8fOT0AEMa"
   "j1NK8BAb2DD79UNRcQKbqkZPDApw2SQlHRe3uOzaFdJf+OYyccqA8Bfr+BCPkDdO"
   "Lhyjqav+Lw+6Z9j2WHDcR46sNDMHDczeT5R+b6K2aVnYzdq5Ujw6iWlYT/M2lQxe"
   "u8yNxlhpGQ88al7IMCTCvBTPLYLYjcG2gNXUSrl13ylj3MPtw2Cm3NL/T6T9lsTq"
   "mvopbrS7tSHWTXLitdX2IIBtD3Oq"))
(define csr (bytevector->x509-certificate-signing-request
	     (base64-decode (string->utf8 csr-string))))
(test-assert (x509-certificate-signing-request? csr))
(test-assert (list? (x509-certificate-signing-request:subject csr)))

;; R6RS doesn't have standard date library, so use string...
(define validity (make-x509-validity "221207102146Z" "351207102146Z"))
(test-assert (x509-validity? validity))

(let ((c (x509-certificate-signing-request:sign csr 100 validity
						ca-cert ca-priv-key)))
  (test-assert (x509-certificate? c))
  (test-assert (x509-certificate:validate c
		(list (make-x509-signature-validator ca-cert)))))

(let* ((extensions (x509-extensions
		    (make-x509-authority-key-identifier-extension
		     (make-x509-authority-key-identifier
		      #vu8(1 2 3 4 5)
		      (x509-general-names
		       (other-name->x509-general-name "1.2.3.4"
		        (make-der-octet-string (string->utf8 "other name")))
		       (rfc822-name->x509-general-name "rfc822-name")
		       (dns-name->x509-general-name "dns-name")
		       (directory-name->x509-general-name '(C "NL"))
		       (ip-address->x509-general-name #vu8(1 2 3 4))
		       (registered-id->x509-general-name "2.3.4.5"))
		     101))))
       (c (x509-certificate-signing-request:sign csr 100 validity
						 ca-cert ca-priv-key
						 extensions)))
  (test-assert (x509-certificate? c))
  (test-equal 3 (x509-certificate:version c))
  (let ((extensions (x509-certificate:extensions c)))
    (test-equal 1 (x509-extensions-length extensions))
    (let ((e (x509-extensions-elements extensions)))
      (test-assert (x509-authority-key-identifier-extension? (car e))))))

(let ((rsa-kp (key-pair-factory:generate-key-pair *key-pair-factory:rsa*))
      (ecdsa-kp (key-pair-factory:generate-key-pair *key-pair-factory:ecdsa*
		 (make-ecdsa-ec-parameter *ec-parameter:p192*)))
      (subject (make-x509-distinguished-names '(C "NL") '(CN "Springkussen"))))
  (let ((rsa-c (make-x509-self-signed-certificate rsa-kp 102 subject validity))
	(ecdsa-c (make-x509-self-signed-certificate
		  ecdsa-kp 102 subject validity
		  (x509-extensions
		   (make-x509-authority-key-identifier-extension
		    (make-x509-authority-key-identifier #vu8(1 2 3 4 6)))))))
    (test-assert (x509-certificate? rsa-c))
    (test-assert 1 (x509-certificate:version rsa-c))
    (test-assert (x509-certificate:validate rsa-c
		  (list (make-x509-signature-validator rsa-c))))
    (test-assert (x509-certificate? ecdsa-c))
    (test-assert 3 (x509-certificate:version ecdsa-c))
    (test-assert (x509-certificate:validate ecdsa-c
		  (list (make-x509-signature-validator ecdsa-c))))))

(let* ((rsa-kp (key-pair-factory:generate-key-pair *key-pair-factory:rsa*))
       (ecdsa-kp (key-pair-factory:generate-key-pair *key-pair-factory:ecdsa*
		  (make-ecdsa-ec-parameter *ec-parameter:sect163k1*)))
       (ca-subject (make-x509-distinguished-names '(C "NL") '(CN "CA")))
       (subject (make-x509-distinguished-names '(C "NL") '(CN "Springkussen")))
       (ca-cert (make-x509-self-signed-certificate ecdsa-kp 103
						   ca-subject validity)))
  (let* ((csr-builder (x509-certificate-signing-request-builder-builder
		       (subject subject)
		       (key-pair ecdsa-kp)
		       (attributes
			(x509-attributes
			 (make-x509-challenge-password-attribute "test")))))
	 (csr (x509-certificate-signing-request-builder:build csr-builder)))
    (let ((c (x509-certificate-signing-request:sign
	      csr 104 validity ca-cert (key-pair-private ecdsa-kp))))
      ;; Self CA
      (test-assert (x509-certificate:validate c
		     (list (make-x509-signature-validator ca-cert)))))))
      


(test-end)
