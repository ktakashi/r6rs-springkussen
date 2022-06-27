#!r6rs
(import (rnrs)
	(springkussen digest descriptor)
	(springkussen digest sha1)
	(srfi :64)
	(testing))

(test-begin "SHA-1 digest")

(define (test-sha1 in out)
  (test-equal out (digest-descriptor:digest sha1-descriptor in))
  (let ((state (digest-descriptor:init sha1-descriptor))
	(o (make-bytevector (digest-descriptor-digest-size sha1-descriptor))))
    (digest-descriptor:process! sha1-descriptor state in 0 1)
    (digest-descriptor:process! sha1-descriptor state in 1)
    (test-equal out (digest-descriptor:done! sha1-descriptor state o))))

(test-assert (digest-descriptor? sha1-descriptor))
(test-equal 20 (digest-descriptor-digest-size sha1-descriptor))
(test-equal "1.3.14.3.2.26" (digest-descriptor-oid sha1-descriptor))

(test-sha1 (string->utf8 "abc")
	   #vu8(#xa9 #x99 #x3e #x36 #x47 #x06 #x81 #x6a #xba #x3e
		#x25 #x71 #x78 #x50 #xc2 #x6c #x9c #xd0 #xd8 #x9d))

(test-sha1
 (string->utf8 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
 #vu8(#x84 #x98 #x3E #x44 #x1C #x3B #xD2 #x6E #xBA #xAE
      #x4A #xA1 #xF9 #x51 #x29 #xE5 #xE5 #x46 #x70 #xF1))

;; 2 blocks
(test-sha1
 (string->utf8 "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras rhoncus mattis lectus, at consequat leo porta sit amet erat curae.")
 (hex-string->bytevector "6BB290DE2CBB5FCF82B0D32EB90F47293A28439F"))

(test-end)
