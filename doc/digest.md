`(springkussen digest)` - Digest APIs
=====================================

This library provides message digest operations.

Below is an example to generate a SHA-256 digest.

```scheme
(import (rnrs)
        (springkussen digest))

(define md (make-digester *digest:sha256*))
(digester:digest md (string->utf8 "Hello Springkussen"))

;; => #vu8( 62  60 91  31 244  20 221 114  97  82 179 225 213  39 101  64
;;         190 142 46 205 186 200 182 122 147 127  64 232 142 186 134 178)
```

###### [Procedure] `digester?` _obj_

Returns `#f` if the given _obj_ is a message digester, otherwise `#f`.

###### [Procedure] `make-digester` _descriptor_

_descriptor_ must be a digest descriptor described below.

Makes a message digester.


**NOTE**: A digester is stateful and not a thread safe object.

Digest APIs are categorised to two parts, high level APIs and low
level APIs.


High level APIs
---------------

The High level APIs basically digests a given bytevector in one go, so
in some cases, it might be a bit too expensive for the memory
usage. E.g. making a digest of huge file. If that's the case, you can
consider to use the low level APIs.

The high level APIs allow users to reuse the digester easily. After the
procedure call, the digester can be reused.

###### [Procedure] `digester:digest` _digester_ _bv_

_digester_ must be a message digester.  
_bv_ must be a bytevector.

Digests the given _bv_ via the _digester_ and returns a bytevector.


###### [Procedure] `digester:digest!` _digester_ _bv_ _out_
###### [Procedure] `digester:digest!` _digester_ _bv_ _out_ _pos_

_digester_ must be a message digester.  
_bv_ must be a bytevector.
_out_ must be a bytevector of size of at least the digest size
_pos_ must be an exact integer if the second form is used.

Digests the given _bv_ via the _digester_ and store the result into the
given _out_.

The result will be stored from _pos_ if the second form is used.

Low level APIs
--------------

###### [Procedure] `digester:init!` _digester_

_digester_ must be a message digester

Initialise the given _digester_.

###### [Procedure] `digester:process!` _digester_ _bv_
###### [Procedure] `digester:process!` _digester_ _bv_ _start_
###### [Procedure] `digester:process!` _digester_ _bv_ _start_ _end_

_digester_ must be a message digester.  
_bv_ must be a bytevector.  
_start_ must be an exact integer if the second or third form is used.  
_end_ must be an exact integer if the third form is used.  

Process the given _bv_ with the givevn _digester_.  
If the _start_ is given, then it process the given _bv_ from the _start_ to 
the end of the bytevector.  
If the _end_ is given, then it process the given _bv_ from the _start_ to 
_end_ of the bytevector.

###### [Procedure] `digester:process!` _digester_ _out_
###### [Procedure] `digester:process!` _digester_ _out_ _pos_

_digester_ must be a message digester.  
_out_ must be a bytevector of size of at least the digest size.  
_pos_ must be an exact integer if the second form is used.

Stores the result of the _digester_ into the _out_.  
If the _pos_ is given, then it stores from the _pos_.

The procedure also invalidates the state, so calling this procedure
twice without initialising raises an `&springkussen`.

### Digester descriptors

###### [Procedure] `digester-descriptor?` _obj_

Returns `#t` if the given _obj_ is a digest descriptor, otherwise `#f`.

###### [Procedure] `digester-descriptor-name` _descriptor_

_descriptor_ must be a digest descriptor.

Returns a name of the digest descriptor. E.g. `SHA-256`.

###### [Procedure] `digester-descriptor-digest-size` _descriptor_

_descriptor_ must be a digest descriptor.

Returns the size of the digest.

###### [Procedure] `digester-descriptor-oid` _descriptor_

_descriptor_ must be a digest descriptor.

Returns the string representation of OID of the digest algorithm.
If the digest algorithm doesn't have OID, then return `#f`.

###### [Digest descriptor] `*digest:md5*`
###### [Digest descriptor] `*digest:sha1*`
###### [Digest descriptor] `*digest:sha224*`
###### [Digest descriptor] `*digest:sha256*`
###### [Digest descriptor] `*digest:sha384*`
###### [Digest descriptor] `*digest:sha512*`
###### [Digest descriptor] `*digest:sha512/224*`
###### [Digest descriptor] `*digest:sha512/256*`

Digest descriptors of the respective algorithms.

NOTE: Obviously, users shouldn't use `MD5` and `SHA-1`, these are supported
for the old systems.
