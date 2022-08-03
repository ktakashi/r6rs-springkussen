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
  (let ((cipher (make-symmetric-cipher aes/cbc key cipher-mode-parameter)))
    (symmetric-cipher:encrypt-bytevector cipher (string->utf8 text))))

(define (decrypt-text key bv)
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

###### [Procedure] `make-symmetric-cipher` _spec_

_spec_ must be a symmetric cipher spec object.

Makes a symmetric cipher.

###### [Procedure] `symmetric-cipher:block-size` _cipher_

_cipher_ must be a symmetric cipher object.

Returns the block size of the given _cipher_.


High level cipher APIs
----------------------

###### [Procedure] `symmetric-cipher:encrypt-bytevector` _cipher_ _symmetric-key_ _bv_
###### [Procedure] `symmetric-cipher:encrypt-bytevector` _cipher_ _symmetric-key_ _parameter_ _bv_
###### [Procedure] `symmetric-cipher:decrypt-bytevector` _cipher_ _symmetric-key_ _bv_
###### [Procedure] `symmetric-cipher:decrypt-bytevector` _cipher_ _symmetric-key_ _parameter_ _bv_

_cipher_ must be a symmetric cipher object.  
_symmetric-key_ must be a symmetric key object.  
_parameter_ must be a cipher parameter, if the second form is used.
_bv_ must be a bytevector.

Encrypts / decrypts given _bv_ with given _cipher_, respectively.

###### [Procedure] `symmetric-key?` _obj_

Returns `#t` if the given _obj_ is a symmetric key object.

###### [Procedure] `make-symmetric-key` _bv_

_bv_ must be a bytevector.

Makes a symmetric key object from the given _bv_.

NOTE: This procedure does **not** check the key length, so it is users'
responsibilty to provide a right sized bytevector.


Low level cipher APIs
---------------------

Low level APIs provide fine-grained controls to users. It requires primer
knowledge of the cipher to use them properly. It is recommended to use
high level APIs unless you know what you are doing.


###### [Procedure] `symmetric-cipher:init!` _cipher_ _op_ _symmetric-key_
###### [Procedure] `symmetric-cipher:init!` _cipher_ _op_ _symmetric-key_ _parameter_

_cipher_ must be a symmetric cipher object.  
_op_ must be a cipher operation described below.  
_symmetric-key_ must be a symmetric key object.  
_parameter_ must be a cipher parameter, if the second form is used.

Initialises the given _cipher_ for the _op_ operation which uses 
_symmetric-key_.  
_parameter_ will be used to setup the cipher mode specified when the
_cipher_ is created.

The procedure overwirtes the previous state of the _cipher_.

###### [Macro] `symmetric-cipher-operation` _op_

A macro to check if the given _op_ identifier is a valid operation for
a symmetric cipher, and returns the symbol of _op_.

The valid operations are:

- `encrypt`: for encryption
- `decrypt`: for decryption

###### [Procedure] `symmetric-cipher:encrypt` _cipher_ _pt_
###### [Procedure] `symmetric-cipher:encrypt` _cipher_ _pt_ _ps_

_cipher_ must be a symmetric cipher object.  
_pt_ must be a bytevector.  
_ps_ must be an exact non-negative integer if the second form is used.

Encrypts the given _pt_ from the _ps_ via the _cipher_ and returns 
a bytevector of the cipher text.  
NOTE: the length of the target plain text `(- (bytevector-length pt) ps)`
must be multiply of the block size of the given _cipher_.

###### [Procedure] `symmetric-cipher:encrypt!` _cipher_ _pt_ _ps_ _ct_ _cs_

_cipher_ must be a symmetric cipher object.  
_pt_ must be a bytevector.  
_ps_ must be an exact non-negative integer.  
_ct_ must be a bytevector.  
_cs_ must be an exact non-negative integer.

Encrypts the given _pt_ from the _ps_ via the _cipher_ and fill the cipher 
text into the _ct_ from the _cs_, then returns an integer represents the
length of the cipher text.  
NOTE: the length of the target plain text `(- (bytevector-length pt) ps)`
must be multiply of the block size of the given _cipher_.

###### [Procedure] `symmetric-cipher:encrypt-last-block` _cipher_ _pt_
###### [Procedure] `symmetric-cipher:encrypt-last-block` _cipher_ _pt_ _ps_

_cipher_ must be a symmetric cipher object.  
_pt_ must be a bytevector.  
_ps_ must be an exact non-negative integer if the second form is used.

Encrypts the given _pt_ from the _ps_ via the _cipher_ and returns 
a bytevector of the cipher text. This procedure pads the given _pt_ if
the _cipher_ has a padding procedure.  
If the _cipher_ doesn't have a padding procedure, then it is users' 
responsibilty to make sure the length of the target bytevector is
multiply of the block size.

###### [Procedure] `symmetric-cipher:encrypt-last-block!` _cipher_ _pt_ _ps_ _ct_ _cs_

_cipher_ must be a symmetric cipher object.  
_pt_ must be a bytevector.  
_ps_ must be an exact non-negative integer.  
_ct_ must be a bytevector.  
_cs_ must be an exact non-negative integer.

Encrypts the given _pt_ from the _ps_ via the _cipher_ and fill the
cipher text into the _ct_ from the _cs_, then returns an integer
represents the length of the cipher text.

This procedure pads the given _pt_ if the _cipher_ has a padding procedure.
The _ct_ must hold the length of **padded** plain text.  

If the _cipher_ doesn't have a padding procedure, then it is users'
responsibilty to make sure the length of the target bytevector is
multiply of the block size.

---
The above encryption procedures raises `&springkussen` if the *cipher*s are
not initialised with `encrypt` operation.

###### [Procedure] `symmetric-cipher:decrypt` _cipher_ _ct_
###### [Procedure] `symmetric-cipher:decrypt` _cipher_ _ct_ _cs_

_cipher_ must be a symmetric cipher object.  
_ct_ must be a bytevector.  
_cs_ must be an exact non-negative integer if the second form is used.

Decrypts the given _ct_ from the _cs_ via the _cipher_ and returns 
a bytevector of the plain text.  
NOTE: the length of the target cipher text `(- (bytevector-length ct) cs)`
must be multiply of the block size of the given _cipher_.

###### [Procedure] `symmetric-cipher:decrypt!` _cipher_ _ct_ _cs_ _pt_ _ps_

_cipher_ must be a symmetric cipher object.  
_ct_ must be a bytevector.  
_cs_ must be an exact non-negative integer.  
_pt_ must be a bytevector.  
_ps_ must be an exact non-negative integer.

Decrypts the given _ct_ from the _cs_ via the _cipher_ and fill the plain 
text into the _pt_ from the _ps_, then returns an integer represents the
length of the plain text.  
NOTE: the length of the target cipher text `(- (bytevector-length ct) cs)`
must be multiply of the block size of the given _cipher_.

###### [Procedure] `symmetric-cipher:decrypt-last-block` _cipher_ _ct_
###### [Procedure] `symmetric-cipher:decrypt-last-block` _cipher_ _ct_ _cs_

_cipher_ must be a symmetric cipher object.  
_ct_ must be a bytevector.  
_cs_ must be an exact non-negative integer if the second form is used.

Decrypts the given _ct_ from the _cs_ via the _cipher_ and returns 
a bytevector of the plain text. This procedure unpads the result of the
decryption if the _cipher_ has a unpadding procedure.  
If the _cipher_ doesn't have a unpadding procedure, then it is users' 
responsibilty to remove excess data of the plain text if exists.

NOTE: the length of the target cipher text `(- (bytevector-length ct) cs)`
must be multiply of the block size of the given _cipher_.

###### [Procedure] `symmetric-cipher:decrypt-last-block!` _cipher_ _ct_ _cs_ _pt_ _ps_

_cipher_ must be a symmetric cipher object.  
_ct_ must be a bytevector.  
_cs_ must be an exact non-negative integer.  
_pt_ must be a bytevector.  
_ps_ must be an exact non-negative integer.

Decrypts the given _ct_ from the _cs_ via the _cipher_ and fill the
plain text into the _pt_ from the _ps_, then returns an integer
represents the length of the cipher text.

This procedure unpads the result of the decryption if the _cipher_ has a
unpadding procedure. The _pt_ may have some intact buffer due to the unpadding.

If the _cipher_ doesn't have a unpadding procedure, then it is users' 
responsibilty to remove excess data of the plain text if exists.

NOTE: the length of the target cipher text `(- (bytevector-length ct) cs)`
must be multiply of the block size of the given _cipher_.

---
The above decryption procedures raises `&springkussen` if the *cipher*s are
not initialised with `decrypt` operation.


###### [Procedure] `symmetric-cipher:done!` _cipher_

_cipher_ must be a symmetric cipher object.

Resets the cipher state.

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
Ciphers provide their parameters and it is users' responsibilty to
choose parameters to be used.

NOTE: Cipher parameter can also be used for asymmetric ciphers.

###### [Procedure] `make-cipher-parameter` _parameter_ _..._

_parameter_ must be a cipher parameter.

Makes a composite cipher parameter from given *parameter*s.

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

