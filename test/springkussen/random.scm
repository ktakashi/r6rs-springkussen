#!r6rs
(import (rnrs)
	(springkussen random)
	(srfi :64)
	(testing))

(test-begin "Secure random generator")

(test-assert (random-generator? fortuna-random-generator))
(test-assert (random-generator? default-random-generator))

(let ((bv (make-bytevector 5))
      (prng default-random-generator))
  (test-equal 5 (random-generator:read-random-bytes! prng bv))
  ;; It's a bit naive test
  (test-assert (not (zero? (bytevector-u8-ref bv 0)))))

(let ((prng default-random-generator))
  (test-assert (bytevector? (random-generator:read-random-bytes prng 5)))
  (let ((bv (random-generator:read-random-bytes prng 5)))
    (test-equal 5 (bytevector-length bv))))

(test-assert (< (random-generator:random default-random-generator 10) 10))

(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
