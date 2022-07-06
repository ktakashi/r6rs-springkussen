R6RS Springkussen
=================

Preface
-------

Springkussen is a Dutch word of __bouncy castle__. You may already have a
clue what this library does.

Springkussen _will be_ a yet another cryptographic library for R6RS scheme
implementations. The goal for this library is to provide comprehensive 
cryptographic operations, including PKCS and/or PKI.

Document
--------

See [./doc/overview.md](./doc/overview.md)

If you are interested in enhancing the library, please also refer the
implementation note: [Implementation notes](./notes.md)

Design
------

Memo for me.

### Directory structure (plan)

- src
  - springkussen
    - conditions
	- asn1
	- misc
	  - base64
	- math
    - cipher
	  - symmetric
	    - scheme
	    - mode
	  - asymmetric
	- digest
	- mac
	- pkcs
- test
- doc


Symmetric ciphers
-----------------

### Encryption schemes

In this library, the following symmetric algorithms are supported

- [x] AES
- [x] DES
- [x] Triple DES
- [x] RC2
- [x] RC5
- [ ] ChaCha20[^1]

The above ciphers are required by
[PKCS#5](https://datatracker.ietf.org/doc/html/rfc8018), though
some of them are deprecated.

We may support more such as `Blowfish`, however that will come
after PKCS, especially #12, is supported.

[^1]: ChaCha20 is a stream cipher. This cipher is needed for CSPRNG

### Encryption modes

In this library the following encryption modes are supported.

- [x] ECB
- [x] CBC
- [ ] Stream[^2]

We may support more, such as counter mode or GCM, however,
the same condition as encryption schemes  would be applied.

[^2]: Psuedo mode for stream ciphers


Asymmetric ciphers
------------------

Asymmetric ciphers are public key ciphers. Signature algorithms are
not included in this category. Signatures will be supported in a
separate category. Here, asymmetric cipher can encrypt and decrypt
given message with public key and private key, respectively.

### Schemes

In this library, the following asymmetric cipher algorithms are supported

- [x] RSA

### Encoding schemes

- [x] PKCS #1 v1.5 encoding
- [x] PKCS #1 v2 OAEP encoding

NOTE: ECC is not in this category as it can't be an asymmetric cipher.


Digest algorithms
-----------------

In this library, the following digest algorithms are supported

- [x] MD5
- [x] SHA-1
- [x] SHA-224
- [x] SHA-256
- [x] SHA-384
- [x] SHA-512
- [x] SHA-512/224
- [x] SHA-512/256

We *will probably* support SHA-3 and other algorithms in the near
future, after PKCS is more or less supported.

NOTE: we support the deprecated and/or vulnerable algorithms for
backward compatibility, but users are strongly recommended **NOT**
to use those algorithms, such as `MD5` or `SHA-1`.


Cryptographically Secure Psuedo Random Number Generator (CSPRNG)
----------------------------------------------------------------

In this library, the following CSPRNG algorithms are supported

- [x] Fortuna
- [ ] ChaCha20

