#!r6rs
(import (rnrs)
	(springkussen asn1 types)
	(springkussen asn1 reader)
	(springkussen asn1 writer)
	(srfi :64)
	(testing))

(test-begin "ASN1 reader")

(define-record-type fake-empty
  (parent <asn1-encodable-object>)
  (protocol (lambda (p)
	      (lambda ()
		;; fake constructed
		((p (lambda (this) (make-der-null))))))))
(define-record-type non-empty
  (parent <asn1-encodable-object>)
  (protocol (lambda (p)
	      (lambda ()
		;; fake constructed
		((p (lambda (this) (make-der-integer 1))))))))


(define (test-asn1-read bv expected)
  (let ((obj (bytevector->asn1-object bv)))
    (test-assert (asn1-object? obj))
    (test-assert bv (asn1-object=? expected obj))))

(test-asn1-read #vu8(1 1 #xFF) (make-der-boolean #t))
(test-asn1-read #vu8(1 1 #x0) (make-der-boolean #f))

;; Integer
(test-asn1-read #vu8(2 2 0 #xFF) (make-der-integer #xFF))
(test-asn1-read #vu8(2 1 #x0) (make-der-integer 0))
(test-asn1-read #vu8(2 2 #xFF 1) (make-der-integer #x-FF))

;; Bit string
(test-asn1-read #vu8(3 2 0 #xFF) (make-der-bit-string #vu8(#xFF)))
(test-asn1-read #vu8(3 2 5 #xFF) (make-der-bit-string #vu8(#xFF) 5))

;; Octet string
(test-asn1-read #vu8(4 0) (make-der-octet-string #vu8()))
(test-asn1-read #vu8(4 3 1 2 3) (make-der-octet-string #vu8(1 2 3)))

;; null
(test-asn1-read #vu8(5 0) (make-der-null))

;; oid
(test-asn1-read #vu8(6 3 42 3 4) (make-der-object-identifier "1.2.3.4"))
(test-asn1-read #vu8(6 9 96 134 72 1 101 3 4 2 1)
		(make-der-object-identifier "2.16.840.1.101.3.4.2.1"))

;; external
(test-asn1-read #vu8(40 22 6 3 42 3 4 2 1 1 4 4 1 2 3 4 162 6 4 4 5 6 7 8)
		(make-der-external "1.2.3.4" 1
				   (make-der-octet-string #vu8(1 2 3 4))
				   (make-der-tagged-object
				    2 #t
				    (make-der-octet-string #vu8(5 6 7 8)))))

;; enumerated
(test-asn1-read #vu8(10 1 1) (make-der-enumerated 1))
(test-asn1-read #vu8(10 1 #xFF) (make-der-enumerated -1))

;; sequence
(test-asn1-read #vu8(48 0) (make-der-sequence '()))
(test-asn1-read #vu8(48 3 1 1 #xFF)
		(make-der-sequence (list (make-der-boolean #t))))

;; set
(test-asn1-read #vu8(49 0) (make-der-set '()))
(test-asn1-read #vu8(49 3 1 1 #xFF) (make-der-set (list (make-der-boolean #t))))

;; numeric string
(test-asn1-read #vu8(18 5 49 50 51 52 53) (make-der-numeric-string "12345"))
(test-asn1-read #vu8(18 6 49 50 51 32 52 53)
		(make-der-numeric-string "123 45"))
;; This is rather weird but we don't check at this moment
(test-asn1-read #vu8(18 7 49 50 51 32 52 53 97)
		(make-der-numeric-string "123 45a"))

;; printable string
(test-asn1-read #vu8(19 8 65 66 67 68 32 69 70 36)
		(make-der-printable-string "ABCD EF$"))

;; T61 string
(test-asn1-read #vu8(20 8 65 66 67 68 32 69 70 36)
		(make-der-t61-string "ABCD EF$"))

;; Videotex string
(test-asn1-read #vu8(21 8 65 66 67 68 32 69 70 36)
		(make-der-videotex-string "ABCD EF$"))

;; IA5 string
(test-asn1-read #vu8(22 8 65 66 67 68 32 69 70 36)
		(make-der-ia5-string "ABCD EF$"))

;; UTC time
(test-asn1-read #vu8(23 13 50 50 48 55 49 50 48 57 49 57 53 49 90)
		(make-der-utc-time "220712091951Z"))

;; Generalized time
(test-asn1-read #vu8(24 13 50 50 48 55 49 50 48 57 49 57 53 49 90)
		(make-der-generalized-time "220712091951Z"))

;; Graphic string
(test-asn1-read #vu8(25 8 65 66 67 68 32 69 70 36)
		(make-der-graphic-string "ABCD EF$"))

;; Visible string
(test-asn1-read #vu8(26 8 65 66 67 68 32 69 70 36)
		(make-der-visible-string "ABCD EF$"))

;; General string
(test-asn1-read #vu8(27 8 65 66 67 68 32 69 70 36)
		(make-der-general-string "ABCD EF$"))

;; Universal string
(test-asn1-read #vu8(28 8 65 66 67 68 32 69 70 36)
		(make-der-universal-string "ABCD EF$"))

;; BMP string
(test-asn1-read #vu8(30 16 0 65 0 66 0 67 0 68 0 32 0 69 0 70 0 36)
		(make-der-bmp-string "ABCD EF$"))

;; UTF8 string
(test-asn1-read #vu8(12 8 65 66 67 68 32 69 70 36)
		(make-der-utf8-string "ABCD EF$"))

;; application specific
(test-asn1-read
 #vu8(#x44 #x5 #x68 #x65 #x6c #x6c #x6f)
 (make-der-application-specific #f OCTET-STRING (string->utf8 "hello")))

(test-asn1-read
 #vu8(112 9 48 7 4 5 104 101 108 108 111)
 (make-der-application-specific #t SEQUENCE
  (asn1-object->bytevector (make-der-sequence
			    (list (make-der-octet-string
				   (string->utf8 "hello")))))))

;; tagged object
;; empty
(test-asn1-read #vu8(161 0) (make-der-tagged-object 1 #t #f))
(test-asn1-read #vu8(129 0) (make-der-tagged-object 1 #f #f))
(test-asn1-read #vu8(161 2 5 0) (make-der-tagged-object 1 #t (make-der-null)))

;; (make-der-tagged-object 1 #f (make-der-integer 1))
;; Above will lose the type info, we reader would only recognise it
;; as a octet string
(test-asn1-read #vu8(129 1 1)
		(make-der-tagged-object 1 #f (make-der-octet-string #vu8(1))))

(test-asn1-read #vu8(161 3 2 1 1)
		(make-der-tagged-object 1 #t (make-der-integer 1)))


(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
