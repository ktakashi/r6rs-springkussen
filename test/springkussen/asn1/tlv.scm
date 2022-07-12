#!r6rs
(import (rnrs)
	(springkussen asn1 tlv)
	(srfi :64)
	(testing))

(test-begin "TLV Parser")

(define (builder b tag data constructed?) (list tag data))

(define tlv-parser (make-tlv-parser builder))

(define (test-tlv expected data)
  (define in (open-bytevector-input-port data))
  (let loop ((r (tlv-parser in)) (expected expected))
    (cond ((and (not r) (null? expected)))
	  ((and r (not (null? expected)))
	   (test-equal (car expected) r)
	   (loop (tlv-parser in) (cdr expected)))
	  (else (test-assert "Unexpected EOF" #f)))))

(test-tlv '((#vu8(#x6F)
		 ((#vu8(#x84) #vu8(#x31 #x50 #x41 #x59 #x2e #x53 #x59 #x53 #x2e #x44 #x44 #x46 #x30 #x31))
		  (#vu8(#xA5)
		       ((#vu8(#x88) #vu8(#x02))
			(#vu8(#x5f #x2d) #vu8(#x65 #x6e)))))))
	  (hex-string->bytevector "6F1A840E315041592E5359532E4444463031A5088801025F2D02656E"))

(test-tlv '((#vu8(#xEF)
		 ((#vu8(#xA0) ((#vu8(#x80) #vu8(1 2 3 4 5))))
		  (#vu8(#xA1) ((#vu8(#x80) #vu8(1 2 3 4 5))))
		  (#vu8(#xA1) ((#vu8(#x80) #vu8(#x12 #x34 #x56))))))
	    (#vu8(#xC9) #vu8()))
	  #vu8(#xef #x19 #xa0 #x7 #x80 #x5 #x1 #x2 #x3 #x4 #x5 #xa1 #x7 #x80 #x5 #x1 #x2 #x3 #x4 #x5 #xa1 #x5 #x80 #x3 #x12 #x34 #x56 #xc9 #x0))
		

(test-end)
(exit (zero? (test-runner-fail-count (test-runner-current))))
