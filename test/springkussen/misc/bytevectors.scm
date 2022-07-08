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

(test-end)
