`(springkussen keystore)` - Keystore APIs
=========================================

This library provides keystore APIs.

Below is an example to load and retrieves keys.

```scheme
#!r6rs
(import (rnrs)
        (springkussen keystore))

;; Suppose pfx.p12 file is located on the load path of
;; open-file-input-port can find.
(let ((ks (call-with-port (open-file-input-port "pfx.p12")
           (lambda (in) (read-pkcs12-keystore in "storepass")))))
  (pkcs12-keystore-secret-key-ref ks "aeskey" "test") ;; -> symmetric-key
  (pkcs12-keystore-private-key-ref ks "springkussen rsa" "test") ;; -> private key
  (pkcs12-keystore-certificate-ref ks "ca-cert") ;; -> x509-certificate
  )
```

For more examples, see [examples/keystore](./examples/keystore).

###### [Procedure] `pkcs12-keystore?` _obj_

Returns `#t` if the given _obj_ is a PKCS#12 keystore, otherwise `#f`.

###### [Macro] `pkcs12-keystore-builder` _(field value) ..._

A macro to build an empty PKCS#12 keystore object.  
_field_ must be one of the followings.

- `prng`: Psuedo random generator, default `default-random-generator`.
- `mac-descriptor`: MAC descriptor, default `*digest:sha256` and `1024`

###### [Procedure] `read-pkcs12-keystore` _password_
###### [Procedure] `read-pkcs12-keystore` _input-port_ _password_

_password_ must be a string.  
_input-port_ must be a binary input port, if the second form is used.

Reads PKCS#12 format from the _input-port_ and constructs PKCS#12 keystore.  
If the first form is used, then the procedure reads from
`(current-input-port)`.

###### [Procedure] `bytevector->pkcs12-keystore` _bv_ _password_

_bv_ must be a bytevector.  
_password_ must be a string.

Reads PKCS#12 format represented by the given _bv_ and constructs PKCS#12
keystore.

###### [Procedure] `write-pkcs12-keystore` _keystore_ _password_
###### [Procedure] `write-pkcs12-keystore` _keystore_ _password_ _output-port_

_keystore_ must be a PKCS#12 keystore object.  
_password_ must be a string.  
_output-port_ must be a binary output port, if the second form is used.

Writes the given PKCS#12 keystore into the given _output-port_. The _password_
is used to encrypt the keystore itself, not the entries.  
If the first form is used then the procedure writes to `(current-output-port)`.

###### [Procedure] `pkcs12-keystore->bytevector` _keystore_ _password_

_keystore_ must be a PKCS#12 keystore object.  
_password_ must be a string.

Converts the given _keystore_ to a bytevector. The _password_ is used to
entrypt the keystore itself, not the entries.

###### [Procedure] `pkcs12-keystore-private-key-ref` _keystore_ _alias_
###### [Procedure] `pkcs12-keystore-private-key-ref` _keystore_ _alias_ _password_

_keystore_ must be a PKCS#12 keystore object.  
_alias_ must be a string.  
_password_ must be a string, if the second form is used.

Retrieves a private key associated to the given _alias_ from the given
_keystore_. If the _alias_ doesn't exist then the procedure returns `#f`  
If the stored private key is entrypted, then _password_ is required.

###### [Procedure] `pkcs12-keystore-private-key-set!` _keystore_ _alias_ _private-key_
###### [Procedure] `pkcs12-keystore-private-key-set!` _keystore_ _alias_ _private-key_ _password_
###### [Procedure] `pkcs12-keystore-private-key-set!` _keystore_ _alias_ _private-key_ _password_ _encryption-algorithm_

_keystore_ must be a PKCS#12 keystore object.  
_alias_ must be a string.  
_private-key_ must be a private key.  
_password_ must be a string, if the second or third form is used.  
_encryption-algorithm_ must be a procedure resolves encryption algorithm.

Sets the given _private-key_ with alias of the given _alias_ into the given
_keystore_.  
If the _password_ is provided, which is highly recommended, then the procedure
encrypts the _private-key_ with specified _encryption-algorithm_.  
The default value of the _encryption-algorithm_ is
`*pbes2-aes256-cbc-pad/hmac-sha256*`. Users can change it to less secure
ones for backward compatibility.

###### [Procedure] `pkcs12-keystore-private-key-delete!` _keystore_ _alias_

_keystore_ must be a PKCS#12 keystore object.  
_alias_ must be a string.

Removes the private key entry associated to the given _alias_ from the
given _keystore_.

###### [Procedure] `pkcs12-keystore-certificate-ref` _keystore_ _alias_

_keystore_ must be a PKCS#12 keystore object.  
_alias_ must be a string.

Retrieves a certificate associated to the given _alias_ from the given
_keystore_. If the _alias_ doesn't exist then the procedure returns `#f`

###### [Procedure] `pkcs12-keystore-certificate-set!` _keystore_ _certificate_
###### [Procedure] `pkcs12-keystore-certificate-set!` _keystore_ _alias_ _certificate_

_keystore_ must be a PKCS#12 keystore object.  
_alias_ must be a stsring if the second form is used.  
_certificate_ must be a X.509 certificate object.

Sets the given _certificate_ with the alias of the given _alias_ into the
given _keystore_.  
If the first form is used, then the procedure uses *certificate*'s subject
name as its _alias_.

###### [Procedure] `pkcs12-keystore-certificate-delete!` _keystore_ _alias_

_keystore_ must be a PKCS#12 keystore object.  
_alias_ must be a string.

Removes the certificate entry associated to the given _alias_ from the
given _keystore_.

###### [Procedure] `pkcs12-keystore-certificate-revocation-list-ref` _keystore_ _alias_

_keystore_ must be a PKCS#12 keystore object.  
_alias_ must be a string.

Retrieves a certificate revocation list associated to the given
_alias_ from the given _keystore_. If the _alias_ doesn't exist then
the procedure returns `#f`

###### [Procedure] `pkcs12-keystore-certificate-revocation-list-set!` _keystore_ _alias_ _crl_

_keystore_ must be a PKCS#12 keystore object.  
_alias_ must be a string.  
_crl_ must be a X.509 certificate revocation list.

Sets the given _crl_ with the alias of the given _alias_ into the
given _keystore_.

###### [Procedure] `pkcs12-keystore-certificate-revocation-list-delete!`

_keystore_ must be a PKCS#12 keystore object.  
_alias_ must be a string.

Removes the certificate revocation list entry associated to the given
_alias_ from the given _keystore_.

###### [Procedure] `pkcs12-keystore-secret-key-ref` _keystore_ _alias_
###### [Procedure] `pkcs12-keystore-secret-key-ref` _keystore_ _alias_ _password_

_keystore_ must be a PKCS#12 keystore object.  
_alias_ must be a string.  
_password_ must be a string, if the second form is used.

Retrieves a secret key associated to the given _alias_ from the given
_keystore_. If the _alias_ doesn't exist then the procedure returns `#f`  
If the stored secret key is entrypted, then _password_ is required.


###### [Procedure] `pkcs12-keystore-secret-key-set!` _keystore_ _alias_ _symmetric-key_
###### [Procedure] `pkcs12-keystore-secret-key-set!` _keystore_ _alias_ _symmetric-key_ _password_
###### [Procedure] `pkcs12-keystore-secret-key-set!` _keystore_ _alias_ _symmetric-key_ _encryption-algorithm_

_keystore_ must be a PKCS#12 keystore object.  
_alias_ must be a string.  
_symmetric-key_ must be a symmetric key.  
_password_ must be a string, if the second or third form is used.  
_encryption-algorithm_ must be a procedure resolves encryption algorithm.

Sets the given _symmetric-key_ with alias of the given _alias_ into the given
_keystore_.  
If the _password_ is provided, which is highly recommended, then the procedure
encrypts the _private-key_ with specified _encryption-algorithm_.  
The default value of the _encryption-algorithm_ is
`*pbes2-aes256-cbc-pad/hmac-sha256*`. Users can change it to less secure
ones for backward compatibility.

###### [Procedure] `pkcs12-keystore-secret-key-delete!` _keystore_ _alias_

_keystore_ must be a PKCS#12 keystore object.  
_alias_ must be a string.

Removes the secret key entry associated to the given _alias_ from the
given _keystore_.


###### [Procedure] `pkcs12-keystore-contains?` _keystore_ _alias_

_keystore_ must be a PKCS#12 keystore object.  
_alias_ must be a string.

Returns `#t` if the given _keystore_ has any entry associated to the given
_alias_. Otherwise `#f`.

###### [Procedure] `pkcs12-keystore-alias-entries` _keystore_ _alias_

_keystore_ must be a PKCS#12 keystore object.  
_alias_ must be a string.

Returns an enum set of entry types associated to the given _alias_ from
the given _keystore_.  
If the _alias_ is not associated, then returns `#f`.

###### [Procedure] `pkcs12-keystore-all-aliases` _keystore_

_keystore_ must be a PKCS#12 keystore object.

Returns a list of all the aliases from the given _keystore_.  
The returning list doesn't have duplicates, use
`pkcs12-keystore-alias-entries` to check which entry the returning
alias has.

###### [Macro] `pkcs12-entry-type` _entry-type_

A macro to return valid entry type. The following entry types are
defained in this libraray:

- `private-key`: private key entry
- `certificate`: certificate entry
- `crl`: certificate revocation list entry
- `secret-key`: secret key entry
- `safe-contents`: safe contents entry.
- `unknown`: unknown type of entry.

NOTE: `safe-contents` and `unknown` entries are not possibile to
create in this library.

###### [Macro] `pkcs12-entry-types` _entry-type_ _..._

_entry-type_ must be a valid entry type identifier described above.

Creates an enum set of entry types.

###### [Procedure] `pkcs12-keystore-add-attribute!` _keystore_ _alias_ _attribute_
###### [Procedure] `pkcs12-keystore-add-attribute!` _keystore_ _alias_ _entry-types_ _attribute_

_keystore_ must be a PKCS#12 keystore object.  
_alias_ must be a string.  
_entry-types_ must be a list of valid entry type symbol or enum set of entry types.  
_attribute_ must be PKCS#12 attribute object.

Adds the given _attribute_ to the entry associated to the given
_alias_ of the given _keystore_.  
If the first form is used, then the procedure adds the _attribute_ to
all entries associated to the _alias_.  
If the second form is used, then the procedure adds only the _entry-types_
entries.

This procedure is particularly useful when trusted certificate entry for
Java keystore.

###### [Procedure] `pkcs12-keystore-delete-entry!` _keystore_ _alias_ _entry-types_

_keystore_ must be a PKCS#12 keystore object.  
_alias_ must be a string.  
_entry-types_ must be a list of valid entry type symbol or enum set of entry types.

Removes the entries of type _entry-types_ associated _alias_ from the
_keystore_.

###### [Procedure] `pkcs12-mac-descriptor?` _obj_

Returns `#t` if the given _obj_ is a PKCS#12 MAC descriptor, otherwise `#f`.

###### [Procedure] `make-pkcs12-mac-descriptor` _digest_ _iteration_

_digest_ must be a digest descriptor.  
_iteration_ must be non negative integer.

Creates a PKCS#12 MAC descriptor object of the _digest_ and _iteration_.

###### [Procedure] `pkcs12-attribute?` _obj_

Returns `#t` if the given _obj_ is a PKCS#12 attribute, otherwise `#f`.

###### [PKCS#12 attribute] `*java-trusted-certificate-attribute*`

PKCS#12 attribute for a certificate entry to make the entry trusted
certificate entry for Java keystore.

###### [Encryption algorithm] `*pkcs12-pbe/sha1-and-des3-cbc*`
###### [Encryption algorithm] `*pkcs12-pbe/sha1-and-des2-cbc*`
###### [Encryption algorithm] `*pkcs12-pbe/sha1-and-rc2-128-cbc*`
###### [Encryption algorithm] `*pkcs12-pbe/sha1-and-rc2-40-cbc*`

Encryption algorithm resolver which can be used
`pkcs12-keystore-private-key-set!` and
`pkcs12-keystore-secret-key-set!` procedures.

They are `pbeWithSHAAnd3-KeyTripleDES-CBC`, `pbeWithSHAAnd2-KeyTripleDES-CBC`,
`pbeWithSHAAnd128BitRC2-CBC` and `pbeWithSHAAnd40BitRC2-CBC`, respectively.

###### [Procedure] `make-pbe-encryption-algorithm` _oid_ _salt-length_ _iteration_

_oid_ must be a string of OID representation.  
_salt-length_ must be a non negative integer.  
_iteration_ must be a non negative integer.

Creates encryption algorithm of PBE. The recoginsing OIDs are:

- 1.2.840.113549.1.12.1.3 for `pbeWithSHAAnd3-KeyTripleDES-CBC`
- 1.2.840.113549.1.12.1.4 for `pbeWithSHAAnd2-KeyTripleDES-CBC`
- 1.2.840.113549.1.12.1.5 for `pbeWithSHAAnd128BitRC2-CBC`
- 1.2.840.113549.1.12.1.6 for `pbeWithSHAAnd40BitRC2-CBC`

Using other OIDs, such as `1.2.840.113549.1.12.1.1` or `1.2.840.113549.1.12.1.2`
would raise a `&springkussen` during encryption process.

This procedure must be used with greate care, especially the _iteration_.
By default this library uses `1000`, and it is recommended to use larger 
number, if you want to make a custom one.

###### [Encryption algorithm] `*pbes2-aes128-cbc-pad/hmac-sha256*`
###### [Encryption algorithm] `*pbes2-aes192-cbc-pad/hmac-sha256*`
###### [Encryption algorithm] `*pbes2-aes256-cbc-pad/hmac-sha256*`

Encryption algorithm resolver which can be used
`pkcs12-keystore-private-key-set!` and
`pkcs12-keystore-secret-key-set!` procedures.

They are `aes128-CBC-PAD`, `aes192-CBC-PAD` and `aes256-CBC-PAD`, respectively.

###### [Procedure] `make-pbes2-encryption-algorithm` _digest_ _salt-size_ _iteration_ _key-length_ _encryption-scheme_

_digest_ must be a digest descriptor.  
_salt-size_ must be a non negative integer.  
_iteration_ must be a non negative integer.  
_key-length_ must be a non negative integer.  
_encryption-scheme_ must be a symmetric scheme desciptor.

Creates encryption algorithm of PBES2. The supporting encryption schemes are

- `*scheme:aes-128*`
- `*scheme:aes-192*`
- `*scheme:aes-256*`

The procedure doesnt' check key length if it's appropriate for the given
_encryption-scheme_. It's users' responsibility to provide a proper size.

This procedure must be used with greate care, especially the _iteration_.
By default this library uses `1000`, and it is recommended to use larger 
number, if you want to make a custom one.
