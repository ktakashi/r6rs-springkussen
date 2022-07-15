#!r6rs
(import (rnrs)
	(springkussen misc bytevectors)
	(srfi :64)
	(testing))

(test-begin "Misc bytevectors")

(define (test-bytevector-s si bv endian)
  (test-equal bv (sinteger->bytevector si endian))
  (test-equal si (bytevector->sinteger bv endian))
  (test-equal bv (sinteger->bytevector (bytevector->sinteger bv endian) endian))
  (test-equal si (bytevector->sinteger (sinteger->bytevector si endian) endian))
  )

(test-bytevector-s #x-FFFF #vu8(255 0 1) (endianness big))
(test-bytevector-s #x-FFFF #vu8(1 0 255) (endianness little))
(test-bytevector-s #x-123456789012 #vu8(237 203 169 135 111 238) (endianness big))
(test-bytevector-s #x-123456789012 #vu8(238 111 135 169 203 237) (endianness little))

(let ((bv #vu8(#x11 #x22 #x33 #x44 #xFF 0 1 2 0 #xFF)))
  (test-equal #x1122 (bytevector->uinteger bv (endianness big) 0 2))
  (test-equal #x22 (bytevector->uinteger bv (endianness big) 1 2))
  (test-equal #x2211 (bytevector->uinteger bv (endianness little) 0 2))
  (test-equal #x22 (bytevector->uinteger bv (endianness little) 1 2))

  (test-equal #x1122 (bytevector->sinteger bv (endianness big) 0 2))
  (test-equal #x22 (bytevector->sinteger bv (endianness big) 1 2))
  (test-equal #x2211 (bytevector->sinteger bv (endianness little) 0 2))
  (test-equal #x22 (bytevector->sinteger bv (endianness little) 1 2))
  (test-equal #x-FFFF (bytevector->sinteger bv (endianness big) 4 7))
  (test-equal #x-FFFE (bytevector->sinteger bv (endianness little) 7))
  )
  
(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
