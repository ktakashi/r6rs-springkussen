`(springkussen signature)` - Signer / Verifier APIs
===================================================

This library provides signer and verifier APIs. Signers sign and
generate signatures. Verifiers verify signatures.

The following example show how to sign and verify a signature

```scheme
#!r6rs
(import (rnrs)
        (springkussen misc base64)
        (springkussen signature))

(define public-key
  (asymmetric-key:import-key *public-key-operation:ecdsa*
   (base64-decode
    (string->utf8
     (string-append
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvkZ7orWucup6USq7EriXpGN+DbjRaFwVv9Oh4O16"
      "5Q71mRVa93APvx8zDuC3u7b9suqNXCkJJ/Dr0l/92IIhZA==")))))

(define private-key
  (asymmetric-key:import-key *private-key-operation:ecdsa*
   (base64-decode
    (string->utf8
     (string-append
      "MHcCAQEEIM8bl4oICQ9KKGUexSiBg1/PG5eKCAkPSihlHsUogYNfoAoGCCqGSM49AwEHoUQDQgAE"
      "vkZ7orWucup6USq7EriXpGN+DbjRaFwVv9Oh4O165Q71mRVa93APvx8zDuC3u7b9suqNXCkJJ/Dr"
      "0l/92IIhZA==")))))

(let ((signer (make-signer *signer:ecdsa* private-key))
      (verifier (make-verifier *verifier:ecdsa* public-key))
      (message (string->utf8 "Hello Springkussen")))
  (signer:sign-message signer message) ;; -> returns a bytevector represents the signature 
  (verifier:verify-signature verifier message (signer:sign-message signer message))) ;; -> #t
```

Below example shows how to generate an ECDSA key pair

```scheme
#!r6rs
(import (rnrs)
        (springkussen signature))

(key-pair-factory:generate-key-pair *key-pair-factory:ecdsa*
  (make-ecdsa-ec-parameter *ec-parameter:p256*))
;; -> key pair object of P-256 curve
```

###### [Procedure] `signer?` _obj_

Returns `#t` if the given _obj_ is a signer object, otherwise `#f`.

###### [Procedure] `make-signer` _descriptor_ _key_
###### [Procedure] `make-signer` _descriptor_ _key_ _parameter_

_descriptor_ must be a signer descriptor, described below.  
_key_ must be a **private** key.  
_parameter_ must be a signature parameter, if the second form is used.

Creates a signer object, which uses the _key_ to sign.

###### [Procedure] `verifier?` _obj_

Returns `#t` if the given _obj_ is a verifier object, otherwise `#f`.

###### [Procedure] `make-verifier` _descriptor_ _key_
###### [Procedure] `make-verifier` _descriptor_ _key_ _parameter_

_descriptor_ must be a signer descriptor, described below.  
_key_ must be a **public** key.  
_parameter_ must be a signature parameter, if the second form is used.

Creates a verifier object, which uses the _key_ to verify.

### Signer descriptor

A signer descriptor holds signing operations for a particular signing
algorithm.

###### [Procedure] `signer-descriptor?` _obj_

Returns `#t` if the given _obj_ is a signer descriptor object, otherwise `#f`.

###### [Procedure] `signer-descriptor-name` _descriptor_

_descriptor_ must be a signer descriptor.

Returns a string represents human readable name of this descriptor.

###### [Signer descriptor] `*signer:rsa*`

The RSA signer descriptor.

###### [Signer descriptor] `*signer:ecdsa*`

The ECDSA signer descriptor.


### Verifier descriptor

###### [Procedure] `verifier-descriptor?` _obj_

Returns `#t` if the given _obj_ is a verifier descriptor object, otherwise `#f`.

###### [Procedure] `verifier-descriptor-name` _descriptor_

_descriptor_ must be a verifier descriptor.

Returns a string represents human readable name of this descriptor.

###### [Verifier descriptor] `*verifier:rsa*`

The RSA verifier descriptor.

###### [Verifier descriptor] `*verifier:ecdsa*`

The ECDSA verifier descriptor.

### Signature parameter

Signature parameter is a compositbale record, like condition on R6RS.  
Signers or verifiers provide their parameters and it is users'
responsibility to choose parameters to be used.

Parameters that can't be used by a signer or a verifier will be ignored.

###### [Procedure] `signature-parameter?` _obj_

Returns `#t` if the given _obj_ is a signature parameter, otherwise `#f`.

###### [Procedure] `make-signature-parameter` _parameter_ _..._

_parameter_ must be a signature parameter.

Makes a composite signature parameter from given *parameter*s.

###### [Procedure] `signature-digest-parameter?` _obj_

Returns `#t` if the given _obj_ is a signature digest parameter, otherwise `#f`.

###### [Procedure] `make-signature-digest-parameter` _digest_

_digest_ must be a digest descriptor.

Makes a signature digest parameter of the given _digest_. This _digest_ is
used to compute a digest of the message which will be used to calculate
a signature.

#### RSA signature parameters

The below signature paramters are used only by RSA signers and verifiers.

###### [Procedure] `rsa-signature-encode-parameter?` _obj_

Returns `#t` if the given _obj_ is a RSA signature encode parameter,
otherwise `#f`.

###### [Procedure] `make-rsa-signature-encode-parameter` _encoder_

_encoder_ must be a RSA encoder, described below.

Makes a RSA signature encode parameter of the _encoder_.  
This parameter will only be used by a RSA signer.

###### [RSA encoder] `pkcs1-emsa-v1.5-encode`

RSASSA-PKCS1-v1_5 encoder.

###### [RSA encoder] `pkcs1-emsa-pss-encode`

RSASSA-PSS encoder. New applications should use this encoder.

###### [Procedure] `rsa-signature-verify-parameter?` _obj_

Returns `#t` if the given _obj_ is a RSA signature verify parameter,
otherwise `#f`.

###### [Procedure] `make-rsa-signature-verify-parameter` _verify_

_verify_ must be a RSA verify, described below.

Makes a RSA signature verify parameter of the _verify_.  
This parameter will only be used by a RSA verifier.

###### [RSA verify] `pkcs1-emsa-v1.5-verify`

RSASSA-PKCS1-v1_5 verify.

###### [RSA verify] `pkcs1-emsa-pss-verify`

RSASSA-PSS verify.

###### [Procedure] `rsa-signature-mgf-digest-parameter?` _obj_

Returns `#t` if the given _obj_ is a RSA signature MGF digest parameter,
otherwise `#f`.

###### [Procedure] `make-rsa-signature-mgf-digest-parameter` _digest_

_digest_ must be a digest descriptor.

Makes a RSA signature MGF digest parameter of the _digest_. This _digest_
is used to generate mask via MGF function.  
This parameter is used only by the RSASSA-PSS encode and verify.

###### [Procedure] `rsa-signature-salt-parameter?` _obj_

Returns `#t` if the given _obj_ is a RSA signature salt parameter,
otherwise `#f`.

###### [Procedure] `make-rsa-signature-salt-parameter` _bv_

_bv_ must be a bytevector.

Makes a RSA signature salt parameter of the _bv_. The salt should be
generated randomly.  
If this parameter isn't specified, then a RSA signer will generate
salt, length of its digest, via a default random generator.  
This parameter is used only by the RSASSA-PSS encode.

###### [Procedure] `rsa-signature-salt-length-parameter?` _obj_

Returns `#t` if the given _obj_ is a RSA signature salt length parameter,
otherwise `#f`.

###### [Procedure] `make-rsa-signature-salt-length-parameter` _length_

_length_ must be an integer.

Makes a RSA signature salt length parameter of the _length_. The length
must be the same length as the verifying signature's salt.  
This parameter is used only by the RSASSA-PSS verify.

#### ECDSA signature parameters

The below signature paramters are used only by ECDSA signers and verifiers.

###### [Procedure] `ecdsa-encode-parameter?` _obj_

Returns `#t` if the given _obj_ is a ECDSA encode parameter, otherwise `#f`.

###### [Procedure] `make-ecdsa-encode-parameter` _encode-type_

_encode-type_ must be a symbol of enum type `ecdsa-signature-encode-type`.

Makes a ECDSA encode parameter of _encode-type_.

###### [Macro] `ecdsa-signature-encode-type` _type_

_type_ must be an identifier.

Checks if the given _type_ is a valid ECDSA encode value and returns 
the symbol of the _type_. The below values are the valid types

- `der`: Let a signer compute a signature of DER encoded value
- `none`: Let a signer compute a signature of bare value

###### [Procedure] `k-generator-parameter?` _obj_

Returns `#t` if the given _obj_ is a k generator parameter, otherwise `#f`.

###### [Procedure] `make-k-generator-parameter` _k-generator_

_k-generator_ must be a procedure accepts two arguments.

Makes a k generator parameter of the _k-generator_.

###### [Procedure] `make-random-k-generator` _random-generator_

_random-generator_ must be a random generator.

Makes a random k generator using the _random-generator_ as its PRNG.


High level APIs
---------------

The high level APIs provides convenient entrance of the signar
and verifier APIs.

###### [Procedure] `signer:sign-message` _signer_ _message_

_signer_ must be a signer.  
_message_ must be a bytevector to be signed.

Signs the given _message_ with the _signer_ and returns the signature
bytevector.

###### [Procedure] `verifier:verify-signature` _verifier_ _message_ _signature_

_verifier_ must be a verifier.  
_message_ must be a bytevector represents the original message.  
_signature_ must be a bytevector represents the signature of the _message_.

Verifies the given _signature_ with the _verifier_ and return the
result of the verification in boolean, `#t` is valid, `#f` is invalid.

Low level APIs
--------------

The low level APIs can be used fine-grained, memory efficiency operations,
such as calculating a signature of a large message or verifying a signature
of a large message.

###### [Procedure] `signer:init!` _signer_

_signer_ must be a signer.

Initialises the given _signer_. If the _signer_ is during the siginig
process, this procedure resets the state.

###### [Procedure] `signer:process!` _signer_ _bv_

_signer_ must be a signer.  
_bv_ must be a bytevector.

Process the given _bv_ for signature calculation.

###### [Procedure] `signer:sign` _signer_

_signer_ must be a signer.

Returns a bytevector represents the signature of the processed message.

###### [Procedure] `verifier:init!` _verifier_

_verifier_ must be a verifier.

Initialises the given _verifier_. If the _verifier_ is during verifying
process, this procedure resets the state.

###### [Procedure] `verifier:process!` _verifier_ _bv_

_verifier_ must be a verifier.  
_bv_ must be a bytevector.

Process the given _bv_ for the signature verification.

###### [Procedure] `verifier:verify` _verifier_ _bv_

_verifier_ must be a verifier.  
_bv_ must be a bytevector, represents the verifying signature.

Verifies the given _bv_ against the processed message and return
the result of verification.  
`#t` means the _bv_ is a valid signature.  
`#f` means the _bv_ is **not** a valid signature.


Asymmetric key operations
-------------------------

###### [Re-exported] `asymmetric-key?`
###### [Re-exported] `asymmetric-key:import-key`
###### [Re-exported] `asymmetric-key:export-key`
###### [Re-exported] `asymmetric-key-operation?`
###### [Re-exported] `*public-key-operation:rsa*`
###### [Re-exported] `*private-key-operation:rsa*`
###### [Re-exported] `key-pair? `
###### [Re-exported] `key-pair-private `
###### [Re-exported] `key-pair-public`
###### [Re-exported] `private-key? `
###### [Re-exported] `public-key?`
###### [Re-exported] `rsa-private-key? `
###### [Re-exported] `rsa-public-key?`
###### [Re-exported] `key-factory?`
###### [Re-exported] `key-factory:generate-key`
###### [Re-exported] `*key-factory:rsa*`
###### [Re-exported] `key-pair-factory?`
###### [Re-exported] `key-pair-factory:generate-key-pair`
###### [Re-exported] `*key-pair-factory:rsa*`
###### [Re-exported] `key-parameter?`
###### [Re-exported] `make-key-parameter`
###### [Re-exported] `rsa-public-key-parameter?`
###### [Re-exported] `make-rsa-public-key-parameter`
###### [Re-exported] `rsa-private-key-parameter?`
###### [Re-exported] `make-rsa-private-key-parameter`
###### [Re-exported] `rsa-crt-private-key-parameter?`
###### [Re-exported] `make-rsa-crt-private-key-parameter`
###### [Re-exported] `random-generator-key-parameter?`
###### [Re-exported] `make-random-generator-key-parameter`
###### [Re-exported] `key-size-key-parameter?`
###### [Re-exported] `make-key-size-key-parameter`
###### [Re-exported] `public-exponent-key-parameter?`
###### [Re-exported] `make-public-exponent-key-parameter`

Above bindings are re-exported from `(springkussen cipher asymmetric)`
library for convenience. For more details, please see
[`(springkussen cipher asymmetric)` - Asymmetric cipher APIs](./asymmetric.md).

###### [Key factory] `*key-factory:ecdsa*`

ECDSA key factory.

###### [Key pair factory] `*key-pair-factory:ecdsa*`

ECDSA key pair factory.

###### [Key operation] `*private-key-operation:ecdsa*`

ECDSA private key operation.

###### [Key operation] `*public-key-operation:ecdsa*`

ECDSA public key operation.

###### [Procedure] `ecdsa-public-key?`

Returns `#t` if the given _obj_ is a ECDSA public key, otherwise `#f`.

###### [Procedure] `ecdsa-private-key?` _obj_

Returns `#t` if the given _obj_ is a ECDSA private key, otherwise `#f`.

###### [Procedure] `signature:export-asymmetric-key` _asymmetric-key_

_asymmetric-key_ must be an asymmetric key.

Exports the given _asymmetric-key_ as a bytevector.  
This is a convenient procedure of `asymmetric-key:export-key`.

###### [Procedure] `ecdsa-public-key-parameter?` _obj_

Returns `#t` if the given _obj_ is a ECDSA public key parameter, otherwise `#f`.

###### [Procedure] `make-ecdsa-public-key-parameter` _x_ _y_

_x_ must be an exact integer.  
_y_ must be an exact integer.

Makes ECDSA public key parameter. The result of the ECDSA public key will
be `ECPoint(x, y)`.

###### [Procedure] `ecdsa-private-key-parameter?` _obj_

Returns `#t` if the given _obj_ is a ECDSA private key parameter,
otherwise `#f`.

###### [Procedure] `make-ecdsa-private-key-parameter` _d_

_d_ must be an exact integer.

Makes ECDSA private key parameter.

###### [Procedure] `ecdsa-ec-parameter?` _obj_

Returns `#t` if the given _obj_ is a ECSA EC parameter, otherwise `#f`.

###### [Procedure] `make-ecdsa-ec-parameter` _ec-parameter_

_ec-parameter_ must be a EC parameter, described below.

Makes a ECDSA EC parameter of the _ec-parameter_.


### EC parameter

###### [Procedure] `ec-parameter?` _obj_

Returns `#t` if the given _obj_ is a EC parameter, otherwise `#f`.

###### [EC parameter] `*ec-parameter:p192*`
###### [EC parameter] `*ec-parameter:secp192r1*`

NIST P-192 EC parameter

###### [EC parameter] `*ec-parameter:p224*`
###### [EC parameter] `*ec-parameter:secp224r1*`

NIST P-224 EC parameter

###### [EC parameter] `*ec-parameter:p256*`
###### [EC parameter] `*ec-parameter:secp256r1*`

NIST P-256 EC parameter

###### [EC parameter] `*ec-parameter:p384*`
###### [EC parameter] `*ec-parameter:secp384r1*`

NIST P-384 EC parameter

###### [EC parameter] `*ec-parameter:p521*`
###### [EC parameter] `*ec-parameter:secp521r1*`

NIST P-521 EC parameter

###### [EC parameter] `*ec-parameter:k163*`
###### [EC parameter] `*ec-parameter:sect163k1*`

NIST K-163 EC parameter

###### [EC parameter] `*ec-parameter:k233*`
###### [EC parameter] `*ec-parameter:sect233k1*`

NIST K-223 EC parameter

###### [EC parameter] `*ec-parameter:k283*`
###### [EC parameter] `*ec-parameter:sect283k1*`

NIST K-283 EC parameter

###### [EC parameter] `*ec-parameter:k409*`
###### [EC parameter] `*ec-parameter:sect409k1*`

NIST K-409 EC parameter

###### [EC parameter] `*ec-parameter:k571*`
###### [EC parameter] `*ec-parameter:sect571k1*`

NIST K-571 EC parameter

###### [EC parameter] `*ec-parameter:b163*`
###### [EC parameter] `*ec-parameter:sect163r2*`

NIST B-163 EC parameter

###### [EC parameter] `*ec-parameter:b233*`
###### [EC parameter] `*ec-parameter:sect233r1*`

NIST B-223 EC parameter

###### [EC parameter] `*ec-parameter:b283*`
###### [EC parameter] `*ec-parameter:sect283r1*`

NIST B-283 EC parameter

###### [EC parameter] `*ec-parameter:b409*`
###### [EC parameter] `*ec-parameter:sect409r1*`

NIST B-409 EC parameter

###### [EC parameter] `*ec-parameter:b571*`
###### [EC parameter] `*ec-parameter:sect571r1*`

NIST B-571 EC parameter

###### [EC parameter] `*ec-parameter:secp192k1*`

secp192k1 EC parameter

###### [EC parameter] `*ec-parameter:secp224k1*`

secp224k1 EC parameter

###### [EC parameter] `*ec-parameter:secp256k1*`

secp256k1 EC parameter

###### [EC parameter] `*ec-parameter:sect163r1*`

sect163r1 EC parameter

###### [EC parameter] `*ec-parameter:sect239k1*`

sect239k1 EC parameter

###### [EC parameter] `*ec-parameter:sect113r1*`

sect113r1 EC parameter
