`(springkussen mac)` - MAC APIs
===============================

This library provides Message Authentication Code (MAC) operations.

Below is an example to generate an HMAC with SHA-256.

```scheme
#!r6rs
(import (rnrs)
        (springkussen digest)
        (springkussen mac))

(define key (string->utf8 "HMAC key"))
(define mac (make-mac *mac:hmac* (make-hmac-parameter key *digest:sha256*)))

(mac:generate-mac mac (string->utf8 "I want this message's MAC"))
;; -> #vu8(144 16 104 42 155 94 155 199 65 144 136 161 100 138 250 161 64 222 188 46 239 174 116 242 113 151 10 137 82 38 234 194)
```

###### [Procedure] `mac?` _obj_

Returns `#t` if the given _obj_ is a MAC, otherwise `#f`.

###### [Procedure] `make-mac` _descriptor_ _parameter_

_descriptor_ must be a MAC descriptor described below.  
_parameter_ must be a MAC pararameter described below.

Makes a MAC.

###### [Procedure] `mac:mac-size` _mac_

_mac_ must be a MAC object.

Returns the size of MAC.

###### [Procedure] `mac:mac-oid` _mac_

_mac_ must be a MAC object.

Returns a string represents OID of the given _mac_, if supported.  
If the OID is not known, then it returns `#f`.


High level APIs
---------------

High level APIs provides a general and convenient usage of the
MAC computation. These APIs are in general suitable for short
messages.

###### [Procedure] `mac:generate-mac` _mac_ _bv_
###### [Procedure] `mac:generate-mac` _mac_ _bv_ _len_

_mac_ must be a MAC object.  
_bv_ must be a bytevector.  
_len_ must be an exact non-negative integer if the second form is used.

Computes MAC from the _bv_ via _mac_ and returns a bytevector of MAC.  
If the second form is used, then the returning bytevector only contains
_len_ length elements.

###### [Procedure] `mac:generate-mac!` _mac_ _bv_ _out_
###### [Procedure] `mac:generate-mac!` _mac_ _bv_ _out_ _pos_
###### [Procedure] `mac:generate-mac!` _mac_ _bv_ _out_ _pos_ _len_

_mac_ must be a MAC object.  
_bv_ must be a bytevector.  
_out_ must be a bytevector.  
_pos_ must be an exact non-negative integer if the second or third form is used.  
_len_ must be an exact non-negative integer if the third form is used.

Computes MAC from the _bv_ via _mac_ and populate the result into the _out_.  
If the second form is used, then it fills the result from the _pos_.  
If the third form is used, then it fills the length of _len_ result from
the _pos_.

Low level APIs
--------------

Low level APIs provides three parts of the MAC computation,
initialisation, processing and finalisation. The APIs are suitable for
long messages, which can't be loaded in memory.

###### [Procedure] `mac:init!` _mac_

_mac_ must be a MAC object.

Initialise the given _mac_. If the given _mac_ is already initialised,
then the procedure discards the previous state and starts new process.

###### [Procedure] `mac:process!` _mac_ _bv_
###### [Procedure] `mac:process!` _mac_ _bv_ _start_
###### [Procedure] `mac:process!` _mac_ _bv_ _start_ _end_

_mac_ must be a MAC object.  
_bv_ must be a bytevector.  
_start_ must be an exact non-negative integer.  
_end_ must be an exact non-negative integer.  

Process the given _bv_ to compute MAC via _mac_.  
If the second form is used, then it takes message from position of _start_.  
If the third form is used, then it takes message from position of _start_ to
the _end_.

###### [Procedure] `mac:done!` _mac_ _out_
###### [Procedure] `mac:done!` _mac_ _out_ _pos_
###### [Procedure] `mac:done!` _mac_ _out_ _pos _len_

_mac_ must be a MAC object.  
_out_ must be a bytevector.  
_pos_ must be an exact non-negative integer.  
_len_ must be an exact non-negative integer.  

Compute MAC of the given _mac_ and store it into the _out_.  
If the second form is used, then it stores from position of the _pos_.  
If the third form is used, then it stores length of _len_ from _pos_.


MAC descriptor
--------------

###### [Procedure] `mac-descriptor?` _obj_

Returns `#t` is the given _obj_ is a MAC descriptor, otherwise `#f`.

###### [Procedure] `mac-descriptor-name` _descriptor_

_descriptor_ must be a MAC descriptor.

Returns the name of this MAC. e.g. `HMAC`

###### [MAC descriptor] `*mac:hmac*`

HMAC descriptor.


MAC parameter
-------------

###### [Procedure] `mac-parameter?` _obj_

Returns `#t` is the given _obj_ is a MAC parameter, otherwise `#f`.

###### [Procedure] `make-mac-parameter` _mac-parameter_ _..._

_mac-parameter_ must be a MAC parameter.

Makes a composite MAC parameter.

###### [Procedure] `make-hmac-parameter` _key_ _digest_

_key_ must be a bytevector.  
_digest_ must be a digest descriptor, described in 
[`(springkussen digest)`](./digest.md).

Makes a HMAC parameter. _key_ represents HMAC key, and _digest_ is the
digest algorithm to be used.
