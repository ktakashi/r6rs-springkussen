R6RS Springkussen
=================

Preface
-------

Springkussen is a Dutch word of __bouncy castle__. You may already have a
clue what this library does.

Springkussen is a yet another cryptographic library for R6RS scheme
implementations. The goal for this library is to provide comprehensive 
cryptographic operations, including PKCS and/or PKI.

Document
--------

See [./doc/README.md](./doc/README.md)

If you are interested in enhancing the library, please also refer the
implementation note: [Implementation notes](./doc/notes.md)

Tested Implementations
----------------------

This library is tested on the below implementations

- Chez Scheme
- Sagittarius

The tests are executed on CI using
[scheme-env](https://github.com/ktakashi/scheme-env).  
To add tested implementations, the implementation must be added to
`scheme-env` first.
