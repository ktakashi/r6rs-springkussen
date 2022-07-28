`(springkussen cipher asymmetric)` - Asymmetric cipher APIs
===========================================================

This library provides asymmetric key ciphers and its APIs.

Below is an example to encrypt an arbitrary text with RSA/OAEPPadding

```scheme
(import (rnrs)
        (springkussen cipher asymmetric))

(define modulus #x00b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf861075c677c81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d)
(define exponent #x010001)
(define private-exponent #x1a502d0eea6c7b69e21d5839101f705456ed0ef852fb47fe21071f54c5f33c8ceb066c62d727e32d26c58137329f89d3195325b795264c195d85472f7507dbd0961d2951f935a26b34f0ac24d15490e1128a9b7138915bc7dbfa8fe396357131c543ae9c98507368d9ceb08c1c6198a3eda7aea185a0e976cd42c22d00f003d9f19d96ea4c9afcbfe1441ccc802cfb0689f59d804c6a4e4f404c15174745ed6cb8bc88ef0b33ba0d2a80e35e43bc90f350052e72016e75b00d357a381c9c0d467069ca660887c987766349fcc43460b4aa516bce079edd87ba164307b752c277ed9528ad3ba0bf1877349ed3b7966a6c240110409bf4d0fade0c68fdadd847fd)

(define rsa-public-key
  (key-factory:generate-key *key-factory:rsa*
   (make-rsa-public-key-parameter modulus exponent)))
(define rsa-private-key
  (key-factory:generate-key *key-factory:rsa*
   (make-rsa-private-key-parameter modulus private-exponent)))

(define rsa/oaep-padding-spec (asymmetric-cipher-spec-builder
                               (scheme *scheme:rsa*)
                               (encoding oaep-encoding)))

(define (rsa:encrypt msg public-key)
  (define cipher (make-asymmetric-cipher rsa/oaep-padding-spec public-key))
  (asymmetric-cipher:encrypt-bytevector cipher msg))

(define (rsa:decrypt msg private-key)
  (define cipher (make-asymmetric-cipher rsa/oaep-padding-spec private-key))
  (asymmetric-cipher:decrypt-bytevector cipher msg))

(let ((cipher-text (rsa:encrypt (string->utf8 "Hello Springkussen") rsa-public-key)))
  (rsa:decrypt cipher-text rsa-private-key))
;; -> #vu8(72 101 108 108 111 32 83 112 114 105 110 103 107 117 115 115 101 110)
;;   = "Hello Springkussen"
```

For key pair generation, you can do like this.

```scheme
(import (rnrs)
        (springkussen cipher asymmetric))

(define key-pair
  (key-pair-factory:generate-key-pair *key-pair-factory:rsa*
   (make-key-size-key-parameter 4096)))

(key-pair-private key-pair) ;; -> RSA private key
(key-pair-public key-pair)  ;; -> RSA public key
```

Cipher APIs
-----------

Asymmetric cipher has the same structure as symmetric cipher, this means
it also uses a cipher spec.

###### [Procedure] `asymmetric-cipher-spec?` _obj_

Returns `#t` if the given _obj_ is a asymmetric cipher spec object.


###### [Macro] `asymmetric-cipher-spec-builder` _(field value) ..._

A macro to build a asymmetric cipher spec object.  
_field_ must be one of the followings

- `scheme`: Encryption scheme, **required**
- `encoding`: Padding scheme, optional, default `pkcs1-v1.5-encoding`

###### [Padding scheme] `pkcs1-v1.5-encoding`

PKCS#1 v1.5 encoding

###### [Padding scheme] `oaep-encoding`

OAEP encoding, for new applications, this should be used.

###### [Procedure] `asymmetric-cipher?` _obj_

Returns `#t` if the given _obj_ is a asymmetric cipher object.

###### [Procedure] `make-asymmetric-cipher` _spec_ _asymmetric-key_
###### [Procedure] `make-asymmetric-cipher` _spec_ _asymmetric-key_ _parameter_

_spec_ must be a asymmetric cipher spec object.  
_symmetric-key_ must be a asymmetric key object.  
_parameter_ must be a cipher parameter, if the second form is used.

Makes a asymmetric cipher.

###### [Procedure] `asymmetric-cipher:encrypt-bytevector` _cipher_ _bv_
###### [Procedure] `asymmetric-cipher:decrypt-bytevector` _cipher_ _bv_

_cipher_ must be a asymmetric cipher object.  
_bv_ must be a bytevector.

Encrypts / decrypts given _bv_ with given _cipher_, respectively.

In this library, it doesn't check if encryption happens with public key
or not. So, it is users responsibility to make sure to choose the
appropriate key for the operation.

### Cipher parameter

###### [Procedure] `make-cipher-parameter` _param_ _..._
###### [Procedure] `cipher-parameter?` _obj_

Re-exported from `(springkussen cipher symmetric)`.  See the `Cipher
parameter` section of [`(springkussen cipher symmetric)` - Symmetric
cipher APIs](./symmetric.md).

#### Encoding parameter

Encoding parameter is a sub type of cipher parameter.

###### [Procedure] `encoding-parameter?` _obj_

Returns `#t` if the given _obj_ is an encoding parameter, otherwise `#f`.

###### [Procedure] `random-generator-encoding-parameter?` _obj_

Returns `#t` if the given _obj_ is an random generator encoding parameter,
otherwise `#f`.

###### [Procedure] `make-random-generator-encoding-parameter` _random-generator_

_random-generator_ must be a random generator.

Makes a random generator encoding parameter. This parameter can be used
for both `oaep-encoding` and `pkcs1-v1.5-encoding`.

###### [Procedure] `digest-encoding-parameter?` _obj_

Returns `#t` if the given _obj_ is a digest encoding parameter, otherwise `#f`.

###### [Procedure] `make-digest-encoding-parameter` _descriptor_

_descriptor_ must be a digest descriptor.

Makes a digest encoding parameter. This parameter can be used for 
`oaep-encoding`

###### [Procedure] `mgf-digest-encoding-parameter?` _obj_

Returns `#t` if the given _obj_ is a MGF digest encoding parameter,
otherwise `#f`.

###### [Procedure] `make-mgf-digest-encoding-parameter` _descriptor_

_descriptor_ must be a digest descriptor.

Makes a MGF digest encoding parameter. This parameter can be used for 
`oaep-encoding`. This parameter controls MGF digest.

###### [Procedure] `label-encoding-parameter?` _obj_

Returns `#t` if the given _obj_ is a label encoding parameter, otherwise `#f`.

###### [Procedure] `make-label-encoding-parameter` _label_

_label_ must be a bytevector represents OAEP encoding label.

Makes a label encoding parameter. This parameter can be used for 
`oaep-encoding`. This parameter controls label of OAPE encoding.


Encryption scheme
-----------------

Encryption scheme has a type called asymmetric scheme descriptor. 
An asymmetric scheme descriptor provides a scheme name.

###### [Procedure] `asymmetric-scheme-decriptor?` _obj_

Returns `#t` if the given _obj_ is a asymmetric scheme descriptor.

###### [Procedure] `asymmetric-scheme-decriptor-name` _asd_

_asd_ must be a asymmetric scheme decriptor.

Returns a encryption scheme name. E.g. `RSA`

###### [Asymmetric scheme decriptor] `*scheme:rsa*`

RSA encryption scheme.


Key operation APIs
------------------

Asymmetric keys have some extra operations, such as key generation.

###### [Procedure] `asymmetric-key?` _obj_

Returns `#t` if the given _obj_ is a asymmetric key object.

###### [Procedure] `asymmetric-key:import-key` _key-operation_ _by_

_key-operation_ must be a asymmetric key operation object.  
_bv_ must be a bytevector represents the appropriate key for 
the given _key-operation_.

Imports an asymmetric key from _bv_ via the _key-operation_.

###### [Procedure] `asymmetric-key:export-key` _key-operation_ _asymmetric-key_

_key-operation_ must be a asymmetric key operation object.  
_asymmetric-key_ must be an asymmetric key.

Exports the given _asymmetric-key_ as a bytevector via the _key-operation_.

###### [Key operation] `*public-key-operation:rsa*`
###### [Key operation] `*private-key-operation:rsa*`

RSA Public key and private key operations, respectively.

###### [Procedure] `key-factory?` _obj_

Returns `#t` if the given _obj_ is a key factory object, otherwise `#f`.

###### [Procedure] `key-factory:generate-key` _kf_ _key-parameter_

_kf_ must be a key factory object.  
_key-parameter_ must be a key parameter object.

Generates a key according to the given _key-parameter_ via the _kf_.

###### [Key factory] `*key-factory:rsa*`

Key factory object for RSA.

###### [Procedure] `key-pair-factory?` _obj_

Returns `#t` if the given _obj_ is a key pair factory object, otherwise `#f`.

###### [Procedure] `key-pair-factory:generate-key` _kpf_
###### [Procedure] `key-pair-factory:generate-key` _kpf_ _key-parameter_

_kpf_ must be a key pair factory object.  
_key-parameter_ must be a key parameter object if the second form is used.

Generates a key pair according to the given _key-parameter_ via the _kpf_.  
If the first form is used, then it tries to generate a default key pair.

###### [Key pair factory] `*key-pair-factory:rsa*`

Key pair factory object for RSA.

###### [Procedure] `key-pair?` _obj_

Returns `#t` if the given _obj_ is a key pair object, otherwise `#f`.

###### [Procedure] `key-pair-private` _kp_

_kp_ must be a key pair object.

Returns the private key of this key pair _kp_.

###### [Procedure] `key-pair-public` _kp_

_kp_ must be a key pair object.

Returns the public key of this key pair _kp_.

###### [Procedure] `private-key?` _obj_

Returns `#t` if the given _obj_ is a private key, otherwise `#f`.

###### [Procedure] `public-key?` _obj_

Returns `#t` if the given _obj_ is a public key, otherwise `#f`.

###### [Procedure] `rsa-private-key?` _obj_

Returns `#t` if the given _obj_ is a RSA private key, otherwise `#f`.

###### [Procedure] `rsa-public-key?` _obj_

Returns `#t` if the given _obj_ is a RSA public key, otherwise `#f`.

### Key parameters

Key parameters specify key specification. For example, modulus of RSA
public key or key length of a generating key. Both key factory and key
pair factory uses the same type, and if the wrong parameter is
specified for a factory, the parameter will be ignored.

###### [Procedure] `key-parameter?` _obj_

Returns `#t` if the given _obj_ is a key parameter, otherwise `#f`.

###### [Procedure] `rsa-public-key-parameter?` _obj_

Returns `#t` if the given _obj_ is a RSA public key parameter, otherwise `#f`.

###### [Procedure] `make-rsa-public-key-parameter` _modulus_ _exponent_

_modulus_ must be an integer represents a RSA modulus.  
_exponent_ must be an integer represents a RSA public exponent.

Makes a RSA public key parameter.

###### [Procedure] `rsa-private-key-parameter?` _obj_

Returns `#t` if the given _obj_ is a RSA private key parameter, otherwise `#f`.

###### [Procedure] `make-rsa-private-key-parameter` _modulus_ _private-exponent_

_modulus_ must be an integer represents a RSA modulus.  
_private-exponent_ must be an integer represents a RSA private exponent.

Makes a RSA private key parameter.

###### [Procedure] `rsa-crt-private-key-parameter?` _obj_

Returns `#t` if the given _obj_ is a RSA CRT private key parameter,
otherwise `#f`.

###### [Procedure] `make-rsa-crt-private-key-parameter` _modulus_ _private-exponent_ _public-exponent_ _p_ _q_ _dP_ _dQ_ _qP_

_modulus_  must be an integer represents a RSA modulus.  
_private-exponent_ must be an integer represents a RSA private exponent.  
_public-exponent_  must be an integer represents a RSA public exponent.  
_p_ must be an integer of prime number.  
_q_ must be an integer of prime number.  
_dP_ must be an integer.  
_dQ_ must ba an integer.  
_qP_ must ben an integer.  

Makes a RSA CRT private key parameter. The parameter doesn't check the
validity of the arguments. It is users' responsibility to make sure
all the arguments satisfy the below equation:

```math
modulus = p * q
private-exponent = e^-1 mod (p - 1) * (q - 1)
dP = private-exponent mod (p - 1)
qP = private-exponent mod (q - 1)
qP = q^-1 mod p
```

###### [Procedure] `random-generator-key-parameter?` _obj_

Returns `#t` if the given _obj_ is a random generator key parameter,
otherwise `#f`.

###### [Procedure] `make-random-generator-key-parameter` _random-generator_

_random-generator_ must be a random generator.

Makes a random generator key parameter.

###### [Procedure] `key-size-key-parameter?` _obj_

Returns `#t` if the given _obj_ is a key size key parameter, otherwise `#f`.

###### [Procedure] `make-key-size-key-parameter` _size_

_size_ must be an integer.

Makes a key size key parameter.

###### [Procedure] `public-exponent-key-parameter?` _obj_

Returns `#t` if the given _obj_ is a public exponent key parameter,
otherwise `#f`.

###### [Procedure] `make-public-exponent-key-parameter` _exponent_

_exponent_ must be an integer.

Makes a public exponent key parameter.
