`(springkussen cms)` - Cryptographic Message Syntax APIs
========================================================

This library provides cryptographic message syntax APIs.

Though the library is not really intended to exposed to outside
of the world. So the functionality of this library is very limited.

```scheme
#!r6rs
(import (rnrs)
        (springkussen cms)
		(springkussen pem)
        (springkussen cipher password))

(define pem-string
  "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHVMEAGCSqGSIb3DQEFDTAzMBsGCSqGSIb3DQEFDDAOBAjme5aQxJazwQICCAAw
FAYIKoZIhvcNAwcECA95ye2Y6WOuBIGQGZuAskbZmlr3EjilrCv92gk7iejiqEbW
CF71VAF+IDkGFiVU5TTLLS76nOdM5c6DhgSWIX97BSrXk/EF4akBrk5Fuh1y5YMw
p5Acg4ZMB76A5uxPLgoo4VViFmPIYRdfXYJvC/8JPkLi03irIoDseahHTgxtGwqP
rsVuKldqIluTiTtcfJ5cXciZMB+DXGoc
-----END ENCRYPTED PRIVATE KEY-----")

(define pem-object (string->pem-object pem-string))

(define key (make-pbe-key "test"))

(cms-encrypted-private-key-info->private-key 
 (pem-object->cms-encrypted-private-key-info pem-object) key)
;; -> private-key
```

Encrypted private key info
--------------------------

###### [Procedure] `cms-encrypted-private-key-info?` _obj_

Returns `#t` if the given _obj_ is encrypted private key info object,
otherwise `#f`.

###### [Procedure] `cms-encrypted-private-key-info->private-key` _encrypted-private-key-info_ _symmetric-key_

_encrypted-private-key-info_ must be an encrypted private key info object.  
_symmetric-key_ must be a symmetric key, including PBE key.

Decrypts the given _encrypted-private-key-info_ and returns a private key
object.  
The decryption algorithm is derived from the _encrypted-private-key-info_
and if the algorithm is not supported, then `&springkussen` is raised.

NOTE: the algorithm can be defined in a different libraries and may require
them to be loaded before the procedure is called. e.g. `(springkussen keystore)`

###### [Procedure] `private-key->cms-encrypted-private-key-info` _private-key_ _symmetric-key_
###### [Procedure] `private-key->cms-encrypted-private-key-info` _private-key_ _symmetric-key_ _algorithm-provider_
###### [Procedure] `private-key->cms-encrypted-private-key-info` _private-key_ _symmetric-key_ _algorithm-provider_ _prng_

_private-key_ must be a private key.  
_symmetric-key_ must be a symmetric key, including PBE key.  
_algorithm-provider_ must be a procedure accepts one argument.  
_prng_ must be a random generator.

Encrypts the given _private-key_ with the given _symmetric-key_ and returns
encrypted private key info object.  
The _symmetric-key_ must correspond with the _algorithm-provider_, if it's
not provided, then `*pbes2-aes256-cbc-pad/hmac-sha256*` is used.  
_prng_ is passed to the _algorithm-provider_.
