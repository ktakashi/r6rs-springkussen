#!r6rs
(import (rnrs)
	(springkussen digest descriptor)
	(springkussen digest sha256)
	(srfi :64)
	(testing))

(test-begin "SHA-256 family digest")

(define (make-sha256-test descriptor)
  (lambda (in out)
    (test-equal out (digest-descriptor:digest descriptor in))
    (let ((state (digest-descriptor:init descriptor))
	  (o (make-bytevector (digest-descriptor-digest-size descriptor))))
      (digest-descriptor:process! descriptor state in 0 1)
      (digest-descriptor:process! descriptor state in 1)
      (test-equal out (digest-descriptor:done! descriptor state o)))))
    
(define test-sha256 (make-sha256-test sha256-descriptor))

(test-assert (digest-descriptor? sha256-descriptor))
(test-equal 32 (digest-descriptor-digest-size sha256-descriptor))
(test-equal "2.16.840.1.101.3.4.2.1" (digest-descriptor-oid sha256-descriptor))

(test-sha256 (string->utf8 "abc")
	     #vu8(#xba #x78 #x16 #xbf #x8f #x01 #xcf #xea
                  #x41 #x41 #x40 #xde #x5d #xae #x22 #x23
		  #xb0 #x03 #x61 #xa3 #x96 #x17 #x7a #x9c
		  #xb4 #x10 #xff #x61 #xf2 #x00 #x15 #xad))

(test-sha256 (string->utf8 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
	     #vu8(#x24 #x8d #x6a #x61 #xd2 #x06 #x38 #xb8 
		  #xe5 #xc0 #x26 #x93 #x0c #x3e #x60 #x39
		  #xa3 #x3c #xe4 #x59 #x64 #xff #x21 #x67 
		  #xf6 #xec #xed #xd4 #x19 #xdb #x06 #xc1))

(test-sha256 (string->utf8 "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras rhoncus mattis lectus, at consequat leo porta sit amet erat curae.")
	     (hex-string->bytevector "6C3BB1420A3679E95D3CCB4C6454328289D903A34E3271CEABFC7637A9CE389E"))

(define test-sha224 (make-sha256-test sha224-descriptor))

(test-assert (digest-descriptor? sha224-descriptor))
(test-equal 28 (digest-descriptor-digest-size sha224-descriptor))
(test-equal "2.16.840.1.101.3.4.2.4" (digest-descriptor-oid sha224-descriptor))

(test-sha224 (string->utf8 "abc")
	     #vu8(#x23 #x09 #x7d #x22 #x34 #x05 #xd8
		  #x22 #x86 #x42 #xa4 #x77 #xbd #xa2
		  #x55 #xb3 #x2a #xad #xbc #xe4 #xbd
		  #xa0 #xb3 #xf7 #xe3 #x6c #x9d #xa7))

(test-sha224 (string->utf8 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
	     #vu8(#x75 #x38 #x8b #x16 #x51 #x27 #x76
		  #xcc #x5d #xba #x5d #xa1 #xfd #x89
		  #x01 #x50 #xb0 #xc6 #x45 #x5c #xb4
		  #xf5 #x8b #x19 #x52 #x52 #x25 #x25))

(test-sha224 (string->utf8 "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras rhoncus mattis lectus, at consequat leo porta sit amet erat curae.")
	     (hex-string->bytevector "4027994520c2c764bef1bcd1e163975161c895e0e710139c9f2df139"))

(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
