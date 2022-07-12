#!r6rs
(import (rnrs)
	(springkussen asn1 types)
	(springkussen asn1 reader)
	(springkussen asn1 writer)
	(srfi :64)
	(testing))

(test-begin "ASN1 reader")

(define (test-asn1-read expected bv)
  (let ((obj (bytevector->asn1-object bv)))
    (test-assert (asn1-object? obj))
    (test-assert bv (asn1-object=? expected obj))))

(test-asn1-read (make-der-boolean #t) #vu8(1 1 #xFF))
(test-asn1-read (make-der-boolean #f) #vu8(1 1 0))

(test-asn1-read (make-der-integer 1) #vu8(2 1 1))
(test-asn1-read (make-der-integer #xFF) #vu8(2 2 0 #xFF))
(test-asn1-read (make-der-integer #x-FF) #vu8(2 2 #xFF 1))

(test-end)
