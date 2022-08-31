#!r6rs
(import (rnrs)
	(springkussen random system)
	(srfi :64)
	(testing))

(test-begin "System")

(let ((bv (make-bytevector 10)))
  (test-equal 10 (read-system-random! bv))
  (test-equal 9 (read-system-random! bv 1))
  (test-equal 7 (read-system-random! bv 2 7)))

(test-end)
(exit (test-runner-fail-count (test-runner-current)))
