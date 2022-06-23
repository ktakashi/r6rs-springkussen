R6RS Springkussen
=================

Preface
-------

Springkussen is a Dutch word of __bouncy castle__. You may already have a
clue what this library does.

Springkussen _will be_ a yet another cryptographic library for R6RS scheme
implementations. The goal for this library is to provide comprehensive 
cryptographic operations, including PKCS and/or PKI.


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

In this library the following symmetric algorithms are supported

- [x] AES
- [x] DES
- [x] Triple DES
- [ ] RC2
- [x] RC5

The above ciphers are required by
[PKCS#5](https://datatracker.ietf.org/doc/html/rfc8018), though
some of them are deprecated.

We may support more such as `Blowfish`, however that will come
after PKCS, especially #12, is supported.

### Encryption modes

In this library the following encryption modes are supported.

- [x] ECB
- [x] CBC

We may support more, such as counter mode or GCM, however,
the same condition as encryption schemes  would be applied.

