`(springkussen cipher password)` - Password based cipher APIs
=============================================================

This library provides password based encryption (PBE) cipher and its APIs.

Below is an example to encrypt an arbitary text.

```scheme
#!r6rs
(import (rnrs)
        (springkussen cipher password))

;; Use PBES2 with AES
(let ((cipher (make-pbe-cipher *pbe:pbes2*
               (make-pbe-cipher-encryption-scheme-parameter *scheme:aes*)))
      (parameter (make-cipher-parameter
                  (make-iv-paramater
                   ;; Initial vector of AES block size
                   #vu8(1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6))
                  (make-pbe-cipher-salt-parameter
                   ;; Salt, length is not defined, but longer is better
                   #vu8(1 2 3 4 5 6 7 8))))
      (key (make-pbe-key "password"))
      (message (string->utf8 "Hello Springkussen")))
  (symmetric-cipher:encrypt-bytevector cipher key parameter message)
  ;; -> #vu8(227 198 67 81 6 146 3 166 171 95 190 112 126 42 164 11 33 110 10 200 50 210 147 11 37 91 231 153 156 171 16 251)
  (utf8->string (symmetric-cipher:decrypt-bytevector cipher key parameter #vu8(227 198 67 81 6 146 3 166 171 95 190 112 126 42 164 11 33 110 10 200 50 210 147 11 37 91 231 153 156 171 16 251)))
  ;; -> Hello Springkussen
  )
```

For more examples, see [examples/cipher/password](./examples/cipher/password).

###### [Procedure] `make-pbe-cipher` _descriptor_ _parameter_

_descriptor_ must be a PBE scheme descriptor, described below.  
_parameter_ must be a cipher parameter, specifying encryption scheme

Creates a PBE cipher.   
PBE cipher is a symmetric cipher, so all the symmetric cipher
operations can be done with a PBE cipher as well.

###### [Procedure] `pbe-scheme-descriptor?` _obj_

Returns `#t` if the given _obj_ is a PBE scheme descriptor, otherwise `#f`.

###### [Procedure] `pbe-scheme-descriptor-name` _descriptor_

_descriptor_ must be a PBE scheme descriptor.

Returns the human readable name of the given _descriptor_.

###### [PBE scheme descriptor] `*pbe:pbes1*`
###### [PBE scheme descriptor] `*pbe:pbes2*`

PBE descriptor of PBES1 and PBES2, respectively.

###### [Procedure] `pbe-key?` _obj_

Returns `#t` if the given _obj_ is a PBE key, otherwise `#f`.  
NOTE: the procedure is a synnonym of `symmetric-key?`.

###### [Procedure] `make-pbe-key` _password_

_password_ must be a string.

Creates a PBE key.  
NOTE: the procedure is a synnonym of `make-symmetric-key`.

### PBE cipher parameters

###### [Procedure] `pbe-cipher-encryption-scheme-parameter?` _obj_

Returns `#t` if the given _obj_ is a PBE cipher encryption scheme parameter,
otherwise `#f`.

###### [Procedure] `make-pbe-cipher-encryption-scheme-parameter` _scheme_

_scheme_ must be a symmetric scheme descriptor.

Creates a PBE cipher encryption scheme parameter.  
This cipher parameter is required by the `make-pbe-cipher` procedure.

###### [Procedure] `pbe-cipher-kdf-parameter?` _obj_

Returns `#t` if the given _obj_ is a PBE cipher KDF parameter,
otherwise `#f`.

###### [Procedure] `make-pbe-cipher-kdf-parameter` _kdf_

_kdf_ must be a KDF procedure, which accepts 4 arguments.

Creates a PBE cipher KDF parameter.  
The detail of _kdf_ is described below section.

###### [Procedure] `pbe-cipher-salt-parameter?` _obj_

Returns `#t` if the given _obj_ is a PBE cipher salt parameter,
otherwise `#f`.

###### [Procedure] `make-pbe-cipher-salt-parameter` _salt_

_salt_ must be a bytevector.

Creates a PBE cipher salt parameter.  
This cipher parameter is required during the PBE encryption or decryption
operation.

###### [Procedure] `pbe-cipher-iteration-parameter?` _obj_

Returns `#t` if the given _obj_ is a PBE cipher iteration parameter,
otherwise `#f`.

###### [Procedure] `make-pbe-cipher-iteration-parameter` _iteration_

_iteration_ must be a non negative integer.

Creates a PBE cipher iteration parameter.  
If this parameter is not specified, then the encryption or decryption
operation uses the default value of `1024`.

###### [Procedure] `pbes2-cipher-encryption-mode-parameter?` _obj_

Returns `#t` if the given _obj_ is a PBE cipher encryption mode
parameter, otherwise `#f`.

###### [Procedure] `make-pbes2-cipher-encryption-mode-parameter` _mode_

_mode_ must be a symmetric encryption mode descriptor.

Creates a PBE cipher encryption mode parameter.  
This parameter is used by the `make-pbe-cipher` procedure, if this
is not specified, it uses `*mode:cbc` as the default value.

###### [Procedure] `pbe-cipher-key-size-parameter?` _obj_

Returns `#t` if the given _obj_ is a PBE cipher key size parameter,
otherwise `#f`.

###### [Procedure] `make-pbe-cipher-key-size-parameter` _key-size_

_key-size_ must be non negative integer.

Creates a PBE cipher key size parameter.  
This parameter is used during the key derivation of PBE to determine
the size of the key. This is only useful when PBES1 with AES without
key size specified scheme is used. i.e. `*scheme:aes*`.


### PBE KDF parameters

###### [Procedure] `pbe-kdf-parameter?` _obj_

Returns `#t` if the given _obj_ is a PBE KDF parameter, otherwise `#f`.

###### [Procedure] `pbe-kdf-digest-parameter?` _obj_

Returns `#t` if the given _obj_ is a PBE KDF digest parameter, otherwise `#f`.  
If the procedure returned `#t` to the _obj_, then `pbe-kdf-parameter?` also
returns `#t`.

###### [Procedure] `make-pbe-kdf-digest-parameter` _digest_ 

_digest_ must be a digest descriptor.

Creates a PBE KDF digest parameter.  
This parameter is used only by PBKDF-1 during the key derivation. If the
parameter is not specified, then it uses SHA-1 as the default value.

###### [Procedure] `pbe-kdf-prf-parameter?` _obj_

Returns `#t` if the given _obj_ is a PBE KDF PRF parameter, otherwise `#f`.  
If the procedure returned `#t` to the _obj_, then `pbe-kdf-parameter?`
also returns `#t`.

###### [Procedure] `make-pbe-kdf-prf-parameter` _prf_

_prf_ must be a procedure accepts one argument and returns two values.

Creates a PBE KDF PRF parameter.  
This parameter is used only by PBKDF-2 during the key derivation. If the
parameter is not specified, then it uses HMAC-SHA1.


#### PBE KDF and PRF

###### [Procedure] `make-pbkdf-1` _parameter_

_parameter_ should be a PBE KDF digest parameter or `#f`.

Creates a PBKDF-1 procedure with digest specified by the _parameter_.  
If the _parameter_ doesn't contain PBE KDF digest parameter, then the
procedure uses SHA1 as the default value.

###### [Procedure] `make-pbkdf-2` _parameter_

_parameter_ should be a PBE KDF PRF parameter or `#f`.

Creates a PBKDF-2 procedure with PRF specified by the _parameter_.  
If the _parameter_ doesn't contain PBE KDF PRF parameter, then the
procedure uses HMAC-SHA1 as the default value.

###### [Procedure] `mac->pbkdf2-prf` _mac_ _parameter_

_mac_ must be a MAC descriptor.  
_parameter_ must be a procedure accepts one argument and returns MAC parameter.

Creates a PRF procedure with MAC of _mac_ with parameter provided by
the _parameter_.

###### [Procedure] `make-partial-hmac-parameter` _digest_

_digest_ must be a digest descriptor.

Creates a partial parameter of HMAC for `mac->pbkdf2-prf`.


Algorithm identifiers
---------------------

PBE is often used with PKIX, below describes some algorithm identifier
providers of particular encryption schemes.

###### [Encryption algorithm] `*pbes2-aes128-cbc-pad/hmac-sha256*`
###### [Encryption algorithm] `*pbes2-aes192-cbc-pad/hmac-sha256*`
###### [Encryption algorithm] `*pbes2-aes256-cbc-pad/hmac-sha256*`

Encryption algorithm resolver which can be used decrypting encrypted
private key.

They are `aes128-CBC-PAD`, `aes192-CBC-PAD` and `aes256-CBC-PAD`, respectively.

###### [Procedure] `make-pbes2-algorithm-identifier-provider` _digest_ _salt-size_ _iteration_ _key-length_ _encryption-scheme_

_digest_ must be a digest descriptor.  
_salt-size_ must be a non negative integer.  
_iteration_ must be a non negative integer.  
_key-length_ must be a non negative integer.  
_encryption-scheme_ must be a symmetric scheme desciptor.

Creates encryption algorithm of PBES2. The supporting encryption schemes are

- `*scheme:aes-128*`
- `*scheme:aes-192*`
- `*scheme:aes-256*`
- `*scheme:rc2*`
- `*scheme:rc5*`
- `*scheme:des*`
- `*scheme:desede*`

The procedure doesnt' check key length if it's appropriate for the given
_encryption-scheme_. It's users' responsibility to provide a proper size.

This procedure must be used with greate care, especially the _iteration_.
By default this library uses `1000`, and it is recommended to use larger 
number, if you want to make a custom one.

NOTE: It is **NOT** recommended to use `RC2`, `RC5`, `DES` or `DESEde`,
those are supported for completeness and compatibility purpose.


Re-exported bindings
--------------------

The below bindings are re-exported from `(springkussen cipher symmetric)`
for convenience.

###### [Re-exported] `symmetric-cipher?`
###### [Re-exported] `symmetric-cipher:encrypt-bytevector`
###### [Re-exported] `symmetric-cipher:decrypt-bytevector`
###### [Re-exported] `symmetric-cipher-operation`
###### [Re-exported] `symmetric-cipher:init!`
###### [Re-exported] `symmetric-cipher:encrypt`
###### [Re-exported] `symmetric-cipher:encrypt!`
###### [Re-exported] `symmetric-cipher:encrypt-last-block`
###### [Re-exported] `symmetric-cipher:encrypt-last-block!`
###### [Re-exported] `symmetric-cipher:decrypt`
###### [Re-exported] `symmetric-cipher:decrypt!`
###### [Re-exported] `symmetric-cipher:decrypt-last-block`
###### [Re-exported] `symmetric-cipher:decrypt-last-block!`
###### [Re-exported] `symmetric-cipher:done!`
###### [Re-exported] `symmetric-scheme-descriptor?`
###### [Re-exported] `symmetric-scheme-descriptor-name`
###### [Re-exported] `symmetric-scheme-descriptor-block-size`
###### [Re-exported] `*scheme:aes*`
###### [Re-exported] `*scheme:aes-128*`
###### [Re-exported] `*scheme:aes-192*`
###### [Re-exported] `*scheme:aes-256*`
###### [Re-exported] `*scheme:des*`
###### [Re-exported] `*scheme:desede*`
###### [Re-exported] `*scheme:rc2*`
###### [Re-exported] `*scheme:rc5*`
###### [Re-exported] `make-cipher-parameter`
###### [Re-exported] `cipher-parameter?`
###### [Re-exported] `mode-parameter?`
###### [Re-exported] `make-iv-paramater`
###### [Re-exported] `iv-parameter?`
###### [Re-exported] `pkcs7-padding`
###### [Re-exported] `no-padding`
