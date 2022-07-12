(import (rnrs)
	(springkussen misc record)
	(srfi :64))

(test-begin "Misc record")

(let ()
  (define-record-type foo (fields bar))
  (define-syntax foo-builder (make-record-builder foo))
  (test-equal #f (foo-bar (foo-builder)))
  (test-equal 'ok (foo-bar (foo-builder (bar 'ok)))))

(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
