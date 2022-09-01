R6RS Springkussen - Overview
============================

Springkussen supports variety of cryptographical operations. The 
below lists are the operations currently supported by the library.

- [Symmetric ciphers](#symmetric-ciphers)
- [Asymmetric ciphers](#asymmetric-ciphers)
- [Password based encryptions](#password-based-encryptions)
- [Psuedo random number generator](#psuedo-random-number-generator)
- [Digest](#digest)
- [MAC](#mac)
- [Signature](#signature)
- [X.509 certificate](#x509-certificate)
- [Keystore](#keystore)

Each section has a list of supported algorithms or will be supported ones.
If the algorithm is already supported, the check box is ticked.


Symmetric ciphers
-----------------

### Encryption schemes

In this library, the following symmetric algorithms are supported.

- [x] AES
- [x] DES
- [x] Triple DES
- [x] RC2
- [x] RC5
- [ ] ChaCha20

[^1]: ChaCha20 is a stream cipher. This cipher is needed for CSPRNG

### Encryption modes

In this library the following encryption modes are supported.

- [x] ECB
- [x] CBC
- [ ] Stream[^2]

[^2]: Psuedo mode for stream ciphers


Asymmetric ciphers
------------------

### Schemes

In this library, the following asymmetric cipher algorithms are supported

- [x] RSA

### Encoding schemes

- [x] PKCS #1 v1.5 encoding
- [x] PKCS #1 v2 OAEP encoding

NOTE: ECC is not in this category as it can't be an asymmetric cipher.


Password based encryptions
--------------------------

### Encryption schemes

In this library, the following PBE schems are supported

- [x] PBES1
- [x] PBES1

### Key derivation function (KDF)

In this library, the following KDFs are supported.

- [x] PBKDF1
- [x] PBKDF2


Psuedo random number generator
------------------------------

Psuedo random number generator in this library means
cryptographically Secure Psuedo Random Number Generator (CSPRNG).

In this library, the following CSPRNG algorithms are supported

- [x] Fortuna
- [ ] ChaCha20


MAC
---

In this library, the following MAC algorithms are supported

- [x] HMAC


Digest
------

In this library, the following digest algorithms are supported

- [x] MD5
- [x] SHA-1
- [x] SHA-224
- [x] SHA-256
- [x] SHA-384
- [x] SHA-512
- [x] SHA-512/224
- [x] SHA-512/256

NOTE: we support the deprecated and/or vulnerable algorithms for
backward compatibility, but users are strongly recommended **NOT**
to use those algorithms, such as `MD5` or `SHA-1`.


Signature
---------

In this library, the following signature algorithms are supported

- [x] RSA
- [x] ECDSA

For RSA signature, the following encodings are supported

- [x] RSASSA-PSS
- [x] RSASSA-PKCS1-v1_5

For ECDSA signature, the following curves are supported

- [x] NIST-P-192 secp192r1
- [x] NIST-P-224 secp224r1
- [x] NIST-P-256 secp256r1
- [x] NIST-P-384 secp384r1
- [x] NIST-K-223 sect223k1
- [x] NIST-K-283 sect283k1
- [x] NIST-K-409 sect409k1
- [x] NIST-K-571 sect571k1
- [x] NIST-B-162 sect163r2
- [x] NIST-B-223 sect223r1
- [x] NIST-B-283 sect283r1
- [x] NIST-B-409 sect409r1
- [x] NIST-B-571 sect571r1
- [x] secp192k1
- [x] secp224k1
- [x] secp256k1
- [x] sect163k1
- [x] sect239k1
- [x] sect113r1

The same curve with different names are listed next to each other.

X.509 certificate
-----------------

In this library, the following X.509 related formats are supported

- [x] X.509 Certificate
- [x] X.509 Certificate Signing Request
- [x] X.509 Certificate Revocation List


Keystore
--------

In this library, the following keystore formats are supported

- [x] PKCS#12
