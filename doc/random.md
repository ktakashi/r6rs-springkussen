`(springkussen random)` - Secure random APIs
============================================

This library provides secure random APIs.

The below example shows how to retrieve random bytes.

```scheme
#!r6rs
(import (rnrs)
        (springkussen random))

(random-generator:read-random-bytes default-random-generator 10)
;; -> #vu8(...) ;; 10 elements each time different
```

**NOTE**:  
The vanilla implementation of entropy provider may not work on
some platform, especially Windows, due to the dependency of
random devices, such as `/dev/urandom`.


###### [Procedure] `random-generator?` _obj_

Returns `#t` if the given _obj_ is a random generator, otherwise `#f`.

###### [Random generator] `fortuna-random-generator` 
###### [Random generator] `default-random-generator`

Random generators supported by this library.  
The `default-random-generator` doesn't specify which algorithm is used,
but one of the supported one.

###### [Procedure] `random-generator:read-random-bytes` _prng_ _len_

_prng_ must be a random generator.  
_len_ must be an exact non negative integer.

Reads random bytes of length _len_ from _prng_.

###### [Procedure] `random-generator:read-random-bytes!` _prng_ _bv_
###### [Procedure] `random-generator:read-random-bytes!` _prng_ _bv_ _start_
###### [Procedure] `random-generator:read-random-bytes!` _prng_ _bv_ _start_ _len_

_prng_ must be a random generator.  
_bv_ must be a bytevector.  
_start_ must be an exact non negative integer if the second / third 
form is used.  
_len_ must be an exact non negative integer if the third form us used.

Reads random bytes of length of given _bv_ from _prng_ and store it 
into _bv_.  
If the second form is used, then the storing random data from the _start_ 
of the _bv_ and the length will be `(- (bytevector-length bv) start)`.  
If the third form is used, then the storing random data from the _start_
of the _bv_ and the length will be _len_.

###### [Procedure] `random-generator:random` _prng_ _size_

_prng_ must be a random generator.  
_size_ must be a exact non negative integer.

Reads random integer range of `[0, size)`.
