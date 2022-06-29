(import (rnrs)
	(springkussen digest)
	(springkussen conditions)
	(srfi :64)
	(testing))

(test-begin "Digest API")

(test-assert (digester? (make-digester *digest:md5*)))
(test-error springkussen-condition? (make-digester 'md5))
(test-error assertion-violation? (make-digester 'md5))

(test-assert (digest-descriptor? *digest:sha1*))
(test-equal "SHA-1" (digest-descriptor-name *digest:sha1*))
(test-equal 20 (digest-descriptor-digest-size *digest:sha1*))
(test-equal "1.3.14.3.2.26" (digest-descriptor-oid *digest:sha1*))

(for-each (lambda (d) (test-assert (digest-descriptor? d)))
	  (list *digest:md5*
		*digest:sha1*
		*digest:sha224*
		*digest:sha256*
		*digest:sha384*
		*digest:sha512*
		*digest:sha512/224*
		*digest:sha512/256*))

(let ((in (string->utf8 "abc"))
      (out (hex-string->bytevector "a9993e364706816aba3e25717850c26c9cd0d89d"))
      (desc *digest:sha1*))
  (let ((digester (make-digester desc)))
    (test-equal out (digester:digest digester in))
    (test-error springkussen-condition?
		(digester:digest! digester in (make-bytevector 0) 0))
    (let ((o (make-bytevector (+ (digest-descriptor-digest-size desc) 1) 0))
	  (tmp (make-bytevector (digest-descriptor-digest-size desc))))
      ;; return the given output bytevector
      (test-assert (eq? o (digester:digest! digester in o 1)))
      (bytevector-copy! o 1 tmp 0 (digest-descriptor-digest-size desc))
      (test-equal out tmp))
    (test-assert (digester? (digester:init! digester)))
    (test-assert (digester? (digester:process! digester in 0 1)))
    (test-assert (digester? (digester:process! digester in 1)))
    (test-equal out (digester:done! digester
		     (make-bytevector (digest-descriptor-digest-size desc))))))

(test-end)
