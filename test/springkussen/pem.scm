#!r6rs
(import (rnrs)
	(springkussen pem)
	(springkussen x509)
	(springkussen cms)
	(springkussen signature)
	(srfi :64))

(test-begin "PEM")

(define (test-pem pem-string pem-pred ->obj obj-pred ->pem)
  (let ((pem-object (string->pem-object pem-string)))
    (test-assert (pem-object? pem-object))
    (test-assert pem-pred (pem-pred pem-object))
    (test-assert obj-pred (->obj pem-object))
    (let ((obj (->obj pem-object)))
      (test-assert
       (pem-pred (string->pem-object (pem-object->string (->pem obj))))))))

(test-pem "-----BEGIN CERTIFICATE-----
MIIBmTCCAUegAwIBAgIBKjAJBgUrDgMCHQUAMBMxETAPBgNVBAMTCEF0bGFudGlz
MB4XDTEyMDcwOTAzMTAzOFoXDTEzMDcwOTAzMTAzN1owEzERMA8GA1UEAxMIQXRs
YW50aXMwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAu+BXo+miabDIHHx+yquqzqNh
Ryn/XtkJIIHVcYtHvIX+S1x5ErgMoHehycpoxbErZmVR4GCq1S2diNmRFZCRtQID
AQABo4GJMIGGMAwGA1UdEwEB/wQCMAAwIAYDVR0EAQH/BBYwFDAOMAwGCisGAQQB
gjcCARUDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzA1BgNVHQEE
LjAsgBA0jOnSSuIHYmnVryHAdywMoRUwEzERMA8GA1UEAxMIQXRsYW50aXOCASow
CQYFKw4DAh0FAANBAKi6HRBaNEL5R0n56nvfclQNaXiDT174uf+lojzA4lhVInc0
ILwpnZ1izL4MlI9eCSHhVQBHEp2uQdXJB+d5Byg=
-----END CERTIFICATE-----"
	  x509-certificate-pem-object?
	  pem-object->x509-certificate
	  x509-certificate?
	  x509-certificate->pem-object)
(test-pem "-----BEGIN X509 CRL-----
MIIB9DCCAV8CAQEwCwYJKoZIhvcNAQEFMIIBCDEXMBUGA1UEChMOVmVyaVNpZ24s
IEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdvcmsxRjBEBgNVBAsT
PXd3dy52ZXJpc2lnbi5jb20vcmVwb3NpdG9yeS9SUEEgSW5jb3JwLiBieSBSZWYu
LExJQUIuTFREKGMpOTgxHjAcBgNVBAsTFVBlcnNvbmEgTm90IFZhbGlkYXRlZDEm
MCQGA1UECxMdRGlnaXRhbCBJRCBDbGFzcyAxIC0gTmV0c2NhcGUxGDAWBgNVBAMU
D1NpbW9uIEpvc2Vmc3NvbjEiMCAGCSqGSIb3DQEJARYTc2ltb25Aam9zZWZzc29u
Lm9yZxcNMDYxMjI3MDgwMjM0WhcNMDcwMjA3MDgwMjM1WjAjMCECEC4QNwPfRoWd
elUNpllhhTgXDTA2MTIyNzA4MDIzNFowCwYJKoZIhvcNAQEFA4GBAD0zX+J2hkcc
Nbrq1Dn5IKL8nXLgPGcHv1I/le1MNo9t1ohGQxB5HnFUkRPAY82fR6Epor4aHgVy
b+5y+neKN9Kn2mPF4iiun+a4o26CjJ0pArojCL1p8T0yyi9Xxvyc/ezaZ98HiIyP
c3DGMNR+oUmSjKZ0jIhAYmeLxaPHfQwR
-----END X509 CRL-----"
	  x509-certificate-revocation-list-pem-object?
	  pem-object->x509-certificate-revocation-list
	  x509-certificate-revocation-list?
	  x509-certificate-revocation-list->pem-object)

(test-pem "-----BEGIN CERTIFICATE REQUEST-----
MIIBWDCCAQcCAQAwTjELMAkGA1UEBhMCU0UxJzAlBgNVBAoTHlNpbW9uIEpvc2Vm
c3NvbiBEYXRha29uc3VsdCBBQjEWMBQGA1UEAxMNam9zZWZzc29uLm9yZzBOMBAG
ByqGSM49AgEGBSuBBAAhAzoABLLPSkuXY0l66MbxVJ3Mot5FCFuqQfn6dTs+9/CM
EOlSwVej77tj56kj9R/j9Q+LfysX8FO9I5p3oGIwYAYJKoZIhvcNAQkOMVMwUTAY
BgNVHREEETAPgg1qb3NlZnNzb24ub3JnMAwGA1UdEwEB/wQCMAAwDwYDVR0PAQH/
BAUDAwegADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAgM/ADA8
AhxBvfhxPFfbBbsE1NoFmCUczOFApEuQVUw3ZP69AhwWXk3dgSUsKnuwL5g/ftAY
dEQc8B8jAcnuOrfU
-----END CERTIFICATE REQUEST-----"
	  x509-certificate-signing-request-pem-object?
	  pem-object->x509-certificate-signing-request
	  x509-certificate-signing-request?
	  x509-certificate-signing-request->pem-object)

(test-pem "-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgVcB/UNPxalR9zDYAjQIf
jojUDiQuGnSJrFEEzZPT/92hRANCAASc7UJtgnF/abqWM60T3XNJEzBv5ez9TdwK
H0M6xpM2q+53wmsN/eYLdgtjgBd3DBmHtPilCkiFICXyaA8z9LkJ
-----END PRIVATE KEY-----"
	  private-key-pem-object?
	  pem-object->private-key
	  private-key?
	  private-key->pem-object)

(test-pem "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHNMEAGCSqGSIb3DQEFDTAzMBsGCSqGSIb3DQEFDDAOBAghhICA6T/51QICCAAw
FAYIKoZIhvcNAwcECBCxDgvI59i9BIGIY3CAqlMNBgaSI5QiiWVNJ3IpfLnEiEsW
Z0JIoHyRmKK/+cr9QPLnzxImm0TR9s4JrG3CilzTWvb0jIvbG3hu0zyFPraoMkap
8eRzWsIvC5SVel+CSjoS2mVS87cyjlD+txrmrXOVYDE+eTgMLbrLmsWh3QkCTRtF
QC7k0NNzUHTV9yGDwfqMbw==
-----END ENCRYPTED PRIVATE KEY-----"
	  cms-encrypted-private-key-info-pem-object?
	  pem-object->cms-encrypted-private-key-info
	  cms-encrypted-private-key-info?
	  cms-encrypted-private-key-info->pem-object)

(test-pem "-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEn1LlwLN/KBYQRVH6HfIMTzfEqJOVztLe
kLchp2hi78cCaMY81FBlYs8J9l7krc+M4aBeCGYFjba+hiXttJWPL7ydlE+5UG4U
Nkn3Eos8EiZByi9DVsyfy9eejh+8AXgp
-----END PUBLIC KEY-----"
	  public-key-pem-object?
	  pem-object->public-key
	  public-key?
	  public-key->pem-object)

;; Appendix A
(test-pem "-----BEGIN X509 CERTIFICATE-----
MIIBHDCBxaADAgECAgIcxzAJBgcqhkjOPQQBMBAxDjAMBgNVBAMUBVBLSVghMB4X
DTE0MDkxNDA2MTU1MFoXDTI0MDkxNDA2MTU1MFowEDEOMAwGA1UEAxQFUEtJWCEw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATwoQSr863QrR0PoRIYQ96H7WykDePH
Wa0eVAE24bth43wCNc+U5aZ761dhGhSSJkVWRgVH5+prLIr+nzfIq+X4oxAwDjAM
BgNVHRMBAf8EAjAAMAkGByqGSM49BAEDRwAwRAIfMdKS5F63lMnWVhi7uaKJzKCs
NnY/OKgBex6MIEAv2AIhAI2GdvfL+mGvhyPZE+JxRxWChmggb5/9eHdUcmW/jkOH
-----END X509 CERTIFICATE-----"
	  x509-certificate-pem-object?
	  pem-object->x509-certificate
	  x509-certificate?
	  x509-certificate->pem-object)

(test-pem "-----BEGIN X.509 CERTIFICATE-----
MIIBHDCBxaADAgECAgIcxzAJBgcqhkjOPQQBMBAxDjAMBgNVBAMUBVBLSVghMB4X
DTE0MDkxNDA2MTU1MFoXDTI0MDkxNDA2MTU1MFowEDEOMAwGA1UEAxQFUEtJWCEw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATwoQSr863QrR0PoRIYQ96H7WykDePH
Wa0eVAE24bth43wCNc+U5aZ761dhGhSSJkVWRgVH5+prLIr+nzfIq+X4oxAwDjAM
BgNVHRMBAf8EAjAAMAkGByqGSM49BAEDRwAwRAIfMdKS5F63lMnWVhi7uaKJzKCs
NnY/OKgBex6MIEAv2AIhAI2GdvfL+mGvhyPZE+JxRxWChmggb5/9eHdUcmW/jkOH
-----END X.509 CERTIFICATE-----"
	  x509-certificate-pem-object?
	  pem-object->x509-certificate
	  x509-certificate?
	  x509-certificate->pem-object)

(test-pem "-----BEGIN NEW CERTIFICATE REQUEST-----
MIIBWDCCAQcCAQAwTjELMAkGA1UEBhMCU0UxJzAlBgNVBAoTHlNpbW9uIEpvc2Vm
c3NvbiBEYXRha29uc3VsdCBBQjEWMBQGA1UEAxMNam9zZWZzc29uLm9yZzBOMBAG
ByqGSM49AgEGBSuBBAAhAzoABLLPSkuXY0l66MbxVJ3Mot5FCFuqQfn6dTs+9/CM
EOlSwVej77tj56kj9R/j9Q+LfysX8FO9I5p3oGIwYAYJKoZIhvcNAQkOMVMwUTAY
BgNVHREEETAPgg1qb3NlZnNzb24ub3JnMAwGA1UdEwEB/wQCMAAwDwYDVR0PAQH/
BAUDAwegADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAgM/ADA8
AhxBvfhxPFfbBbsE1NoFmCUczOFApEuQVUw3ZP69AhwWXk3dgSUsKnuwL5g/ftAY
dEQc8B8jAcnuOrfU
-----END NEW CERTIFICATE REQUEST-----"
	  x509-certificate-signing-request-pem-object?
	  pem-object->x509-certificate-signing-request
	  x509-certificate-signing-request?
	  x509-certificate-signing-request->pem-object)

(test-end)
(exit (test-runner-fail-count (test-runner-current)))
	
