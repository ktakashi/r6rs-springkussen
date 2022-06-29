`(springkussen conditions)` - Base condition library
====================================================

`(springkussen conditions)` provides a base conditions, which is 
`&springkussen`.

###### [Condition type] `&springkussen`

A basic condition type for R6RS Springkussen.

###### [Procedure] `springkussen-condition?` _obj_

Returns `#t` if the given _obj_ is a condition and 
contains `&springkussen`.

###### [Procedure] `springkussen-assertion-violation` _who_ _message_ _irr ..._

Raises a condition, which is composed with `&springkussen` and `&assertion`

This procedure must be used when assertion failed, such as input validation.

###### [Procedure] `springkussen-error` _who_ _message_ _irr ..._

Raises a condition, which is composed with `&springkussen` and `&error`

This procedure must be used when a runtime error happens, such as 
signature verification failed.
