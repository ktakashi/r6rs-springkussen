#!r6rs
(import (rnrs)
	(springkussen random descriptor)
	(springkussen random fortuna)
	(srfi :64)
	(testing))

;;; I couldn't find a test vector, so just a simple check
(test-begin "Fortuna")

(test-equal "Fortuna" (random-descriptor-name fortuna-descriptor))
(test-equal 1024 (random-descriptor-export-size fortuna-descriptor))

(let ((state (random-descriptor:start fortuna-descriptor))
      (fd fortuna-descriptor))
  (random-descriptor:add-entropy! fd state (string->utf8 "Hello"))
  (random-descriptor:ready! fd state)
  (let ((bv (make-bytevector 32)))
    (test-equal 32 (random-descriptor:read! fd state bv)))
  (let ((bv (make-bytevector 7)))
    (test-equal 7 (random-descriptor:read! fd state bv)))
  (random-descriptor:done! fd state))

(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
