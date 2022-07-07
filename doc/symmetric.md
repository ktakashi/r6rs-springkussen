`(springkussen cipher symmetric)` - Symmetric cipher APIs
=========================================================

This library provides symmetric key ciphers and its APIs.

Below is an example to encrypt an arbitrary text with AES/CBC.

```scheme
(import (rnrs)
        (springkussen cipher symmetric))

(define aes/cbc 
  (symmetric-cipher-spec-builder
   (scheme *scheme:aes*)
   (mode   *mode:cbc*)))

(define cipher-mode-parameter
  (make-mode-parameter
   (make-iv-paramater
    ;; IV must be the same as the block size.
    ;; NOTE: this is an example, so don't use this in production code.
    ;;       IV must be generated properly with secure random generator
    (make-bytevector (symmetric-scheme-descriptor-block-size *scheme:aes*) 0))))

;; AES uses key size of 16 bytes to 32 bytes, but here we use 16
(define key (make-symmetric-key #vu8(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)))

(define (encrypt-text key text)
  ;; A cipher may not be reusable, if it holds a state, such as IV
  (let ((cipher (make-symmetric-cipher aes/cbc key cipher-mode-parameter)))
    (symmetric-cipher:encrypt-bytevector cipher (string->utf8 text))))

(define (decrypt-text key bv)
  ;; A cipher may not be reusable, if it holds a state, such as IV
  (let ((cipher (make-symmetric-cipher aes/cbc key cipher-mode-parameter)))
    (utf8->string (symmetric-cipher:decrypt-bytevector cipher bv))))

(decrypt-text key (encrypt-text key "Jumping on Springkussen"))
;; -> "Jumping on Springkussen"
```

Cipher APIs
-----------

A cipher needs to be built via a cipher spec. A cipher spec holds
how / what the cipher does, such ash encryption scheme, encryption
mode, and so on.

A symmetric cipher is not always a block cipher like AES. It can also be
a stream cipher, such as ChaCha. Block cipher and stream cipher may have
a different specification. It is users' responsibility to choose the
right options to build a cipher.


###### [Procedure] `symmetric-cipher-spec?` _obj_

Returns `#t` if the given _obj_ is a symmetric cipher spec object.


###### [Macro] `symmetric-cipher-spec-builder` _(field value) ..._

A macro to build a symmetric cipher spec object.  
_field_ must be one of the followings

- `scheme`: Encryption scheme, **required**
- `mode`: Encryption mode, **required**
- `padding`: Padding scheme, optional, default `pkcs7-padding`

###### [Procedure] `symmetric-cipher?` _obj_

Returns `#t` if the given _obj_ is a symmetric cipher object.

###### [Procedure] `make-symmetric-cipher` _spec_ _symmetric-key_
###### [Procedure] `make-symmetric-cipher` _spec_ _symmetric-key_ _parameter_

_spec_ must be a symmetric cipher spec object.  
_symmetric-key_ must be a symmetric key object.  
_parameter_ must be a cipher parameter, if the second form is used.

Makes a symmetric cipher.

NOTE: Most of the ciphers are stateful, such as CBC mode.

###### [Procedure] `symmetric-cipher:encrypt-bytevector` _cipher_ _bv_
###### [Procedure] `symmetric-cipher:decrypt-bytevector` _cipher_ _bv_

_cipher_ must be a symmetric cipher object.  
_bv_ must be a bytevector.

Encrypts / decrypts given _bv_ with given _cipher_, respectively.

###### [Procedure] `symmetric-key?` _obj_

Returns `#t` if the given _obj_ is a symmetric key object.

###### [Procedure] `make-symmetric-key` _bv_

_bv_ must be a bytevector.

Makes a symmetric key object from the given _bv_.

NOTE: This procedure does **not** check the key length, so it is users'
responsibilty to provide a right sized bytevector.


Encryption scheme
-----------------

Encryption scheme has a type called symmetric scheme descriptor. 
A symmetric scheme descriptor provides a scheme name and its 
block size if it's available.

For naming convension, _ssd_ implies symmetric scheme descriptor.

###### [Procedure] `symmetric-scheme-decriptor?` _obj_

Returns `#t` if the given _obj_ is a symmetric scheme descriptor.

###### [Procedure] `symmetric-scheme-decriptor-name` _ssd_

_ssd_ must be a symmetric scheme decriptor.

Returns a encryption scheme name. E.g. `AES`

###### [Procedure] `symmetric-scheme-decriptor-block-size` _ssd_

_ssd_ must be a symmetric scheme decriptor.

Returns a block size of the encryption scheme. If the encryption
scheme is for stream cipher, then it returns `#f`.

###### [Symmetric scheme decriptor] `*scheme:aes*`
###### [Symmetric scheme decriptor] `*scheme:aes-128*`
###### [Symmetric scheme decriptor] `*scheme:aes-192*`
###### [Symmetric scheme decriptor] `*scheme:aes-256*`

AES encryption schemes. The first one accepts key size of 16 to 32.  
The second one to forth one accepts specific key size of 16, 24 and 32,
respectively.

###### [Symmetric scheme decriptor] `*scheme:rc5*`

RC5 encryption scheme.

###### [Symmetric scheme decriptor] `*scheme:des*`
###### [Symmetric scheme decriptor] `*scheme:desede*`

DES and DESede (TripleDES) encryption scheme.

###### [Symmetric scheme decriptor] `*scheme:rc2*`

RC2 encryption scheme.

NOTE: DES, DESede and RC2  encryption schemes are considered 
not secure. So, do not use them for a new application.


Encryption mode
---------------

Encryption mode has a type called symmetric mode descriptor.
A symmetric mode decriptor provides a mode name.

For naming convension, _smd_ implies symmetric scheme descriptor.

###### [Procedure] `symmetric-mode-decriptor?` _obj_

Returns `#t` if the given _obj_ is a symmetric mode descriptor.

###### [Procedure] `symmetric-mode-decriptor-name` _smd_

_smd_ must be a symmetric mode decriptor.

Returns a encryption mode name. E.g. `ECB`

###### [Symmetric mode decriptor] `*mode:ecb*`
###### [Symmetric mode decriptor] `*mode:cbc*`

Encryption modes. The name implies which encryption mode it is.


### Cipher parameter

Cipher parametetr is a compositable record, like condition on R6RS. 
Ciphers should provide appropriate parameters and it is users
responsibilty to choose parameters to be used.

NOTE: Cipher parameter can also be used for asymmetric ciphers.

###### [Procedure] `make-cipher-parameter` _param_ _..._

Makes a composite cipher parameter from given *param*s.

###### [Procedure] `cipher-parameter?` _obj_

Returns `#t` if the given _obj_ is a cipher parameter.


### Mode parameter

Encryption mode may require its parameter. For example, CBC requires
initial vector (IV).

Mode parameter is a sub type of cipher parameter.

###### [Procedure] `mode-parameter?` _obj_

Returns `#t` if the given _obj_ is a mode parameter.

###### [Procedure] `round-parameter?` _obj_

Returns `#f` if the given _obj_ is a round mode parameter.

###### [Procedure] `make-round-parameter` _i_

_bv_ must be a bytevector with right size.

Makes a round mode parameter.  
A round mode parameter may be used to for key round.

NOTE: This parameter is not frequently used.


###### [Procedure] `iv-parameter?` _obj_

Returns `#f` if the given _obj_ is a IV mode parameter.

###### [Procedure] `make-iv-parameter` _bv_

_bv_ must be a bytevector with right size.

Makes a IV mode parameter.


Padding
-------

A block cipher requires the size of plain text to be multiple of
its block size. To make sure this happens, we can use a padding
mechanis.

A padding mechanis is a mere procedure, which returns two values,
padder and unpadder.

###### [Procedure] `pkcs7-padding`

A padding mechanism conforms PKCS#7 padding.

