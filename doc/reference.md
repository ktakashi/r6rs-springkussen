R6RS Springkussen - Users' reference
====================================

R6RS Springkussen[^1] is a yet another cryptographic library written in
R6RS portable Scheme. The goal of this library is providing comprehensive
cryptographical operations.

[^1]: Springkussen is a Dutch word of _bouncy castle_

User Libraries
--------------

R6RS Springkussen doesn't provide `(springkussen)` library, instead it
provides multiple libraries per categories.

Below is the list of libraries:

- [`(springkussen cipher symmetric)`](./symmetric.md): Symmetric cipher APIs
- [`(springkussen cipher asymmetric)`](./asymmetric.md): Asymmetric cipher APIs
- [`(springkussen cipher password)`](./password.md): Password based cipher APIs
- [`(springkussen cms)`](./cms.md): Cryptographic Message Syntax APIs
- [`(springkussen conditions)`](./conditions.md): Defines base conditions
- [`(springkussen digest)`](./digest.md): Digest APIs
- [`(springkussen keystore)`](./keystore.md): Keystore APIs
- [`(springkussen mac)`](./mac.md): MAC APIs
- [`(springkussen random)`](./random.md): Secure random generator APIs
- [`(springkussen pem)`](./pem.md): PEM APIs
- [`(springkussen signature)`](./signature.md): Signer and verifier APIs

The libraries not listed above or procedures not documented are subjected
to be changed in the future releases. It is own risk to use.
