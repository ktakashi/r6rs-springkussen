#!r6rs
(import (rnrs)
	(springkussen asn1 types)
	(springkussen asn1 writer)
	(srfi :64)
	(testing))

(test-begin "ASN.1 writer")

(define-record-type fake-empty
  (parent <asn1-encodable-object>)
  (protocol (lambda (p)
	      (lambda ()
		;; fake constructed
		((p (lambda (this out) (put-bytevector out #vu8(#x20 0)))))))))
(define-record-type non-empty
  (parent <asn1-encodable-object>)
  (protocol (lambda (p)
	      (lambda ()
		;; fake constructed
		((p (lambda (this out)
		      (put-bytevector out #vu8(#x20 1 0)))))))))

(define (test-asn1-writer expected obj)
  (let ((bv (asn1-object->bytevector obj)))
    (test-equal expected bv)))

;; boolean
(test-asn1-writer #vu8(1 1 #xFF) (make-der-boolean #t))
(test-asn1-writer #vu8(1 1 #x0) (make-der-boolean #f))

;; sequence
(test-asn1-writer #vu8(48 0) (make-der-sequence '()))
(test-asn1-writer #vu8(48 3 32 1 0) (make-der-sequence (list (make-non-empty))))

;; set
(test-asn1-writer #vu8(49 0) (make-der-set '()))
(test-asn1-writer #vu8(49 3 32 1 0) (make-der-set (list (make-non-empty))))


;; application specific
(test-asn1-writer
 #vu8(#x44 #x5 #x68 #x65 #x6c #x6c #x6f)
 (make-der-application-specific #f OCTET-STRING (string->utf8 "hello")))

(test-asn1-writer
 #vu8(#x64 #x5 #x68 #x65 #x6c #x6c #x6f)
 (make-der-application-specific #t OCTET-STRING (string->utf8 "hello")))

;; tagged object
;; empty
(test-asn1-writer #vu8(161 0) (make-der-tagged-object 1 #f #f))
(test-asn1-writer #vu8(161 0) (make-der-tagged-object 1 #f (make-fake-empty)))
(test-asn1-writer #vu8(161 2 32 0)
		  (make-der-tagged-object 1 #t (make-fake-empty)))

(test-asn1-writer #vu8(161 1 0) (make-der-tagged-object 1 #f (make-non-empty)))
(test-asn1-writer #vu8(161 3 32 1 0)
		  (make-der-tagged-object 1 #t (make-non-empty)))

(test-end)
