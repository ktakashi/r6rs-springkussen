#!r6rs
(import (rnrs)
	(springkussen digest descriptor)
	(springkussen digest sha512)
	(srfi :64)
	(testing))

(test-begin "SHA-512 family digest")

(define (make-sha512-test descriptor)
  (lambda (in out)
    (test-equal out (digest-descriptor:digest descriptor in))
    (let ((state (digest-descriptor:init descriptor))
	  (o (make-bytevector (digest-descriptor-digest-size descriptor))))
      (digest-descriptor:process! descriptor state in 0 1)
      (digest-descriptor:process! descriptor state in 1)
      (test-equal out (digest-descriptor:done! descriptor state o)))))
    
(define test-sha512 (make-sha512-test sha512-descriptor))

(test-assert (digest-descriptor? sha512-descriptor))
(test-equal 64 (digest-descriptor-digest-size sha512-descriptor))
(test-equal "2.16.840.1.101.3.4.2.3" (digest-descriptor-oid sha512-descriptor))

(test-sha512 (string->utf8 "abc")
	     #vu8(#xdd #xaf #x35 #xa1 #x93 #x61 #x7a #xba
		  #xcc #x41 #x73 #x49 #xae #x20 #x41 #x31
		  #x12 #xe6 #xfa #x4e #x89 #xa9 #x7e #xa2
		  #x0a #x9e #xee #xe6 #x4b #x55 #xd3 #x9a
		  #x21 #x92 #x99 #x2a #x27 #x4f #xc1 #xa8
		  #x36 #xba #x3c #x23 #xa3 #xfe #xeb #xbd
		  #x45 #x4d #x44 #x23 #x64 #x3c #xe8 #x0e
		  #x2a #x9a #xc9 #x4f #xa5 #x4c #xa4 #x9f))

(test-sha512 (string->utf8 "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
	     #vu8(#x8e #x95 #x9b #x75 #xda #xe3 #x13 #xda
		  #x8c #xf4 #xf7 #x28 #x14 #xfc #x14 #x3f
		  #x8f #x77 #x79 #xc6 #xeb #x9f #x7f #xa1
		  #x72 #x99 #xae #xad #xb6 #x88 #x90 #x18
		  #x50 #x1d #x28 #x9e #x49 #x00 #xf7 #xe4
		  #x33 #x1b #x99 #xde #xc4 #xb5 #x43 #x3a
		  #xc7 #xd3 #x29 #xee #xb6 #xdd #x26 #x54
		  #x5e #x96 #xe5 #x5b #x87 #x4b #xe9 #x09))

(define two-blocks-data
  "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus molestie odio sit amet tortor accumsan ullamcorper. Pellentesque luctus felis vel urna tempus condimentum. Nulla semper dignissim nisl in imperdiet. Pellentesque scelerisque viverra quam sed.")
;; 2 blocks
(test-sha512 (string->utf8 two-blocks-data)
	     (hex-string->bytevector "B68635963C32441B22EBFD7F00DB114C9A87032CF796A5CB9352CA161CA5D29AE862AE5956038DDB22AC2B118357DA27D30B1BC4AD546C2481D2B11467198AFC"))


(define test-sha384 (make-sha512-test sha384-descriptor))

(test-assert (digest-descriptor? sha384-descriptor))
(test-equal 48 (digest-descriptor-digest-size sha384-descriptor))
(test-equal "2.16.840.1.101.3.4.2.2" (digest-descriptor-oid sha384-descriptor))

(test-sha384 (string->utf8 "abc")
	     #vu8(#xcb #x00 #x75 #x3f #x45 #xa3 #x5e #x8b
		  #xb5 #xa0 #x3d #x69 #x9a #xc6 #x50 #x07
		  #x27 #x2c #x32 #xab #x0e #xde #xd1 #x63
		  #x1a #x8b #x60 #x5a #x43 #xff #x5b #xed
		  #x80 #x86 #x07 #x2b #xa1 #xe7 #xcc #x23
		  #x58 #xba #xec #xa1 #x34 #xc8 #x25 #xa7))

(test-sha384 (string->utf8 "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
	     #vu8(#x09 #x33 #x0c #x33 #xf7 #x11 #x47 #xe8
		  #x3d #x19 #x2f #xc7 #x82 #xcd #x1b #x47
		  #x53 #x11 #x1b #x17 #x3b #x3b #x05 #xd2
		  #x2f #xa0 #x80 #x86 #xe3 #xb0 #xf7 #x12
		  #xfc #xc7 #xc7 #x1a #x55 #x7e #x2d #xb9
		  #x66 #xc3 #xe9 #xfa #x91 #x74 #x60 #x39))

;; 2 blocks
(test-sha384 (string->utf8 two-blocks-data)
	     (hex-string->bytevector "63035e46d55c1dd6f90e65a8b5c6280ba0b8ec44b9318187b65b593fb5b3483a456dd622b4ca56f6aaadc94f1ca63201"))

(test-end)
