`(springkussen cipher symmetric)` - Symmetric cipher APIs
=========================================================

This library provides symmetric key ciphers and its APIs.

Below is an example to encrypt a arbitrary text with AES/CBC.

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

Makes a symmetric cipher.  
_spec_ must be a symmetric cipher spec object.  
_symmetric-key_ must be a symmetric key object.  
_parameter_ must be a mode parameter, if the second form is used.

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
