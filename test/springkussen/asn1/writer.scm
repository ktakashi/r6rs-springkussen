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

;; Integer
(test-asn1-writer #vu8(2 2 0 #xFF) (make-der-integer #xFF))
(test-asn1-writer #vu8(2 1 #x0) (make-der-integer 0))
(test-asn1-writer #vu8(2 2 #xFF 1) (make-der-integer #x-FF))

;; Bit string
(test-asn1-writer #vu8(3 2 0 #xFF) (make-der-bit-string #vu8(#xFF)))
(test-asn1-writer #vu8(3 2 5 #xFF) (make-der-bit-string #vu8(#xFF) 5))

;; Octet string
(test-asn1-writer #vu8(4 0) (make-der-octet-string #vu8()))
(test-asn1-writer #vu8(4 3 1 2 3) (make-der-octet-string #vu8(1 2 3)))

;; null
(test-asn1-writer #vu8(5 0) (make-der-null))

;; oid
(test-asn1-writer #vu8(6 3 42 3 4) (make-der-object-identifier "1.2.3.4"))
(test-asn1-writer #vu8(6 9 96 134 72 1 101 3 4 2 1)
		  (make-der-object-identifier "2.16.840.1.101.3.4.2.1"))

;; external
(test-asn1-writer #vu8(40 22 6 3 42 3 4 2 1 1 4 4 1 2 3 4 162 6 4 4 5 6 7 8)
		  (make-der-external "1.2.3.4" 1
				     (make-der-octet-string #vu8(1 2 3 4))
				     (make-der-tagged-object
				      2 #t
				      (make-der-octet-string #vu8(5 6 7 8)))))

;; enumerated
(test-asn1-writer #vu8(10 1 1) (make-der-enumerated 1))
(test-asn1-writer #vu8(10 1 #xFF) (make-der-enumerated -1))

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
