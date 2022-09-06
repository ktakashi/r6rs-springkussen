`(springkussen pem)` - PEM APIs
===============================

This library provides PEM APIs. The library follows 
[RFC 7468](https://www.rfc-editor.org/rfc/rfc7468), thus it does not
recognise headers.

The following shows how to write key pairs in PEM format.

```scheme
#!r6rs
(import (rnrs)
        (springkussen signature)
	(springkussen pem))

(define key-pair (key-pair-factory:generate-key-pair *key-pair-factory:ecdsa*))

(write-pem-object (public-key->pem-object (key-pair-public key-pair)))
(write-pem-object (private-key->pem-object (key-pair-private key-pair)))
```

For more examples, see [examples/pem](./examples/pem).

PEM object
----------

PEM object represents PEM label and content. It can only be read from
a string or file, or converted from supported objects.

###### [Procedure] `pem-object?` _obj_

Returns `#t` if the given _obj_ is a PEM object, otherwise `#f`.

###### [Procedure] `read-pem-object`
###### [Procedure] `read-pem-object` _input_

_input_ must be a textual input port, if the second form is used.

Reads a PEM object from the given _input_.  
If the first form is used, then `(current-input-port)` is used.

If the _input_ contains invalid PEM format, then `&springkussen` is raised.

###### [Procedure] `string->pem-object` _string_

_string_ must be a valid PEM string, including label.

Converts the given _string_ to PEM object.

If the _string_ contains invalid PEM format, then `&springkussen` is raised.

###### [Procedure] `write-pem-object` _pem-object_
###### [Procedure] `write-pem-object` _pem-object_ _output_

_pem-object_ must be a PEM object.  
_output_ must be a textual output port, if the second form is used.

Writes the given _pem-object_ to the _output_.  
If the first is used, then `(current-output-port)` is used.

###### [Procedure] `pem-object->string` _pem-object_

_pem-object_ must be a PEM object.

Converts given _pem-object_ to a string representation.


X.509 certificate support
-------------------------

The library supports X.509 certificate PEM read and write. It supports
the following label during reading.

- `CERTIFICATE`
- `X509 CERTIFICATE`
- `X.509 CERTIFICATE`

And it writes with `CERTIFICATE` as the RFC 7468 specifies.

###### [Procedure] `x509-certificate-pem-object?` _obj_

Returns `#t` if the given _obj_ is a PEM object and its label is
one of the above ones, otherwise `#f`.

###### [Procedure] `pem-object->x509-certificate` _pem-object_

_pem-object_ must satisfy ``x509-certificate-pem-object?`.

Converts given _pem-object_ to a X.509 certificate object.

###### [Procedure] `x509-certificate->pem-object` _x509-certificate_

_x509-certificate_ must be a X.509 certificate object.

Converts given _x509-certificate_ to a PEM object.

X.509 certificate request support
---------------------------------

The library supports X.509 certificate signing request PEM read and
write. It supports the following label during reading.

- `CERTIFICATE REQUEST`
- `NEW CERTIFICATE REQUEST`

And it writes with `CERTIFICATE REQUEST` as the RFC 7468 specifies.

###### [Procedure] `x509-certificate-signing-request-pem-object?` _obj_

Returns `#t` if the given _obj_ is a PEM object and its label is
one of the above ones, otherwise `#f`.

###### [Procedure] `pem-object->x509-certificate-signing-request` _pem-object_

_pem-object_ must satisfy `x509-certificate-signing-request-pem-object?`.

Converts given _pem-object_ to a X.509 certificate signing request object.

###### [Procedure] `x509-certificate-signing-request->pem-object` _csr_

_csr_ must be a X.509 certificate signing request object.

Converts given _csr_ to a PEM object.



X.509 CRL support
-----------------

The library supports X.509 certificate revocation list PEM read and
write. It supports the following label during reading.

- `X509 CRL`
- `CRL`

And it writes with `X509 CRL` as the RFC 7468 specifies.

###### [Procedure] `x509-certificate-revocation-list-pem-object?` _obj_

Returns `#t` if the given _obj_ is a PEM object and its label is
one of the above ones, otherwise `#f`.

###### [Procedure] `pem-object->x509-certificate-revocation-list` _pem-object_

_pem-object_ must satisfy `x509-certificate-revocation-list-pem-object?`.

Converts given _pem-object_ to a X.509 certificate revocation list object.

###### [Procedure] `x509-certificate-revocation-list->pem-object` _crl_

_crl_ must be a X.509 certificate revocation list object.

Converts given _crl_ to a PEM object.


Private key support
-------------------

The library supports private key PEM read and write. It supports the
following label during both reading and writing.

- `PRIVATE KEY`

###### [Procedure] `private-key-pem-object?` _obj_

Returns `#t` if the given _obj_ is a PEM object and its label is
one of the above ones, otherwise `#f`.

###### [Procedure] `pem-object->private-key` _pem-object_

_pem-object_ must satisfy `private-key-pem-object?`.

Converts given _pem-object_ to a private key object.


###### [Procedure] `private-key->pem-object` _private-key_

_private-key_ must be a private key object.

Converts given _private-key_ to a PEM object.


Public key support
------------------

The library supports public key PEM read and write. It supports the
following label during both reading and writing.

- `PUBLIC KEY`


###### [Procedure] `public-key-pem-object?` _obj_

Returns `#t` if the given _obj_ is a PEM object and its label is
one of the above ones, otherwise `#f`.

###### [Procedure] `pem-object->public-key` _pem-object_

_pem-object_ must satisfy `public-key-pem-object?`.

Converts given _pem-object_ to a public key object.

###### [Procedure] `public-key->pem-object` _public-key_

_public-key_ must be a private key object.

Converts given _public-key_ to a PEM object.


Encrypted private key info support
----------------------------------

The library supports encrypted private key info PEM read and write. It
supports the following label during both reading and writing.

- `ENCRYPTED PRIVATE KEY`

###### [Procedure] `cms-encrypted-private-key-info-pem-object?` _obj_

Returns `#t` if the given _obj_ is a PEM object and its label is
one of the above ones, otherwise `#f`.

###### [Procedure] `pem-object->cms-encrypted-private-key-info` _pem-object_

_pem-object_ must satisfy `cms-encrypted-private-key-info-pem-object?`.

Converts given _pem-object_ to a public key object.

###### [Procedure] `cms-encrypted-private-key-info->pem-object` _encrypted-private-key-info_

_encrypted-private-key-info_ must be an encrypted private key info object.

Converts given _encrypted-private-key-info_ to a PEM object.
