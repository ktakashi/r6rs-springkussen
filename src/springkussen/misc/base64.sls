;;; -*- mode:scheme; coding:utf-8; -*-
;;;
;;; springkussen/misc/base64.sls - Base64 encode / decode
;;;  
;;;   Copyright (c) 2022  Takashi Kato  <ktakashi@ymail.com>
;;;   
;;;   Redistribution and use in source and binary forms, with or without
;;;   modification, are permitted provided that the following conditions
;;;   are met:
;;;   
;;;   1. Redistributions of source code must retain the above copyright
;;;      notice, this list of conditions and the following disclaimer.
;;;  
;;;   2. Redistributions in binary form must reproduce the above copyright
;;;      notice, this list of conditions and the following disclaimer in the
;;;      documentation and/or other materials provided with the distribution.
;;;  
;;;   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;;;   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;;;   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;;;   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;;;   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;;;   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
;;;   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;;;   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;;;   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;;   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;;   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;  

;; Basically copy&paste from Sagittarius' (rfc base64)
#!r6rs
(library (springkussen misc base64)
    (export base64-encode
	    base64url-encode ;; bonus
	    base64-decode
	    base64url-decode ;; bonus
	    ;; Maybe when we implement PEM reader
	    ;; open-base64-encode-input-port
	    ;; open-base64-encode-output-port
	    ;; open-base64-decode-input-port
	    ;; open-base64-decode-output-port

	    base64-encode-parameter? base64-encode-parameter-builder
	    )
    (import (rnrs)
	    (springkussen misc record))

(define-syntax define-decode
  (syntax-rules ()
    ((_ name table)
     (define (name in)
       (if (bytevector? in)
	   (name (open-bytevector-input-port in))
	   (let-values (((out e) (open-bytevector-output-port)))
	     (define decoder (make-base64-decoder table))
	     (define (put b) (put-u8 out b))
	     (define (get) (get-u8 in))
	     (do () ((decoder get put) (e)))))))))

(define-decode base64-decode *decode-table*)
(define-decode base64url-decode *decode-url-table*)

;; decode port
(define (make-base64-decoder decode-table)
  (define buffer (make-bytevector 4))
  (define buffer-size 0)
  (lambda (get put)
    (define (fill!)
      (let loop ()
	(if (= buffer-size 4)
	    'full
	    (let ((b (get)))
	      (cond ((eof-object? b) 'end)
		    ((negative? b) 'cont) ;; keep		
		    ((and (< 32 b 128) (vector-ref decode-table (- b 32))) =>
		     (lambda (b)
		       (bytevector-u8-set! buffer buffer-size b)
		       (set! buffer-size (+ buffer-size 1))
		       (loop)))
		    (else (loop)))))))
    (define (check b) (>= b 0))
    (define lshift bitwise-arithmetic-shift-left)
    (define rshift bitwise-arithmetic-shift-right)
    (define (decode put b0 b1 b2 b3)
      (when (and (check b0) (check b1))
	(put (bitwise-and (bitwise-ior (lshift b0 2) (rshift b1 4)) #xFF))
	(when (check b2)
	  (put (bitwise-and (bitwise-ior (lshift b1 4) (rshift b2 2)) #xFF))
	  (when (check b3)
	    (put (bitwise-and (bitwise-ior (lshift b2 6)  b3) #xFF))))))
    (define (do-it put size)
      (case size
	;; we at least need 2 bytes ;)
	((2) (decode put
		     (bytevector-u8-ref buffer 0)
		     (bytevector-u8-ref buffer 1)
		     -1 -1))
	((3) (decode put
		     (bytevector-u8-ref buffer 0)
		     (bytevector-u8-ref buffer 1)
		     (bytevector-u8-ref buffer 2)
		     -1))
	((4) (decode put
		     (bytevector-u8-ref buffer 0)
		     (bytevector-u8-ref buffer 1)
		     (bytevector-u8-ref buffer 2)
		     (bytevector-u8-ref buffer 3)))))
    (case (fill!)
      ((full) (do-it put buffer-size) (set! buffer-size 0) #f)
      ((end)  (do-it put buffer-size) (set! buffer-size 0) #t)
      ((cont) #f))))

(define-syntax define-encode
  (syntax-rules ()
    ((_ name table lw pad)
     (define name
       (case-lambda
	((in) (name in #f))
	((in param)
	 (if (bytevector? in)
	     (name (open-bytevector-input-port in) param)
	     (let-values (((out e) (open-bytevector-output-port)))
	       (define line-width
		 (or (and param (base64-encode-parameter-line-width param)) lw))
	       (define padding?
		 (or (and param (base64-encode-parameter-padding?)) pad))
	       (define (put v) (put-u8 out (or v #x0a)))
	       (define (get) (get-u8 in))
	       (define encoder (make-base64-encoder table line-width padding?))
	       (do () ((encoder get put) (e)))))))))))
(define-record-type base64-encode-parameter
  (fields line-width padding?))
(define-syntax base64-encode-parameter-builder
  (make-record-builder base64-encode-parameter))

(define-encode base64-encode *encode-table* 76 #t)
(define-encode base64url-encode *encode-url-table* #f #f)

(define (make-base64-encoder encode-table line-width padding?)
  (define max-col (and line-width (> line-width 0) (- line-width 1)))
  (define col 0)
  (define buffer (make-bytevector 3))
  (define buffer-size 0)

  (lambda (get real-put)
    (define (check-col)
      (when max-col
	(if (= col max-col)
	    (begin
	      (real-put #f) ;; so that implementation may choose end line
	      (set! col 0))
	    (set! col (+ col 1)))))
    (define (put i)
      (real-put (vector-ref encode-table i))
      (check-col))
    (define (fill!)
      (define (ret v size)
	(set! buffer-size size)
	v)
      (let loop ((i buffer-size))
	(if (= i 3)
	    (ret 'full i)
	    (let ((b (get)))
	      (cond ((eof-object? b) (ret 'end i))
		    ((negative? b) (ret 'cont i))
		    (else (bytevector-u8-set! buffer i b) (loop (+ i 1))))))))
    
    (define lshift bitwise-arithmetic-shift-left)
    (define rshift bitwise-arithmetic-shift-right)
    (define ior bitwise-ior)
    (define (encode b0 b1 b2)
      (when (>= b0 0)
	(put (rshift (bitwise-and #xFC b0) 2))
	(let ((b (lshift (bitwise-and #x03 b0) 4)))
	  (cond ((negative? b1) (put b) (when padding? (put 64) (put 64)))
		(else
		 (put (ior b (rshift (bitwise-and #xF0 b1) 4)))
		 (let ((b (lshift (bitwise-and #x0F b1) 2)))
		   (cond ((negative? b2) (put b) (when padding? (put 64)))
			 (else
			  (put (ior b (rshift (bitwise-and #xC0 b2) 6)))
			  (put (bitwise-and #x3F b2))))))))))
    (define (do-it size)
      (case size
	((1) (encode (bytevector-u8-ref buffer 0)
		     -1
		     -1))
	((2) (encode (bytevector-u8-ref buffer 0)
		     (bytevector-u8-ref buffer 1)
		     -1))
	((3) (encode (bytevector-u8-ref buffer 0)
		     (bytevector-u8-ref buffer 1)
		     (bytevector-u8-ref buffer 2)))))
    (case (fill!)
      ((full) (do-it buffer-size) (set! buffer-size 0) #f)
      ((end)  (do-it buffer-size) (set! buffer-size 0) #t)
      ((cont) #f))))


(define *decode-table*
  ;;    !   "   #   $   %   &   '   (   )   *   +   ,   -   .   /
  #(#f  #f  #f  #f  #f  #f  #f  #f  #f  #f  #f  62  #f  #f  #f  63  
  ;;0   1   2   3   4   5   6   7   8   9   :   ;   <   =   >   ?
    52  53  54  55  56  57  58  59  60  61  #f  #f  #f  #f  #f  #f
  ;;@   A   B   C   D   E   F   G   H   I   J   K   L   M   N   O
    #f  0   1   2   3   4   5   6   7   8   9   10  11  12  13  14
  ;;P   Q   R   S   T   U   V   W   X   Y   Z   [   \   ]   ^   _
    15  16  17  18  19  20  21  22  23  24  25  #f  #f  #f  #f  #f
  ;;`   a   b   c   d   e   f   g   h   i   j   k   l   m   n   o
    #f  26  27  28  29  30  31  32  33  34  35  36  37  38  39  40
  ;;p   q   r   s   t   u   v   w   x   y   z   {   |   }   ~
    41  42  43  44  45  46  47  48  49  50  51  #f  #f  #f  #f  #f
    ))

(define *encode-table*
  (vector-map char->integer
     ;;0   1   2   3   4   5   6   7   8   9   10  11  12  13  14  15
   #(#\A #\B #\C #\D #\E #\F #\G #\H #\I #\J #\K #\L #\M #\N #\O #\P
     ;;16  17  18  19  20  21  22  23  24  25  26  27  28  29  30  31
     #\Q #\R #\S #\T #\U #\V #\W #\X #\Y #\Z #\a #\b #\c #\d #\e #\f
     ;;32  33  34  35  36  37  38  39  40  41  42  43  44  45  46  47
     #\g #\h #\i #\j #\k #\l #\m #\n #\o #\p #\q #\r #\s #\t #\u #\v
     ;;48  49  50  51  52  53  54  55  56  57  58  59  60  61  62  63
     #\w #\x #\y #\z #\0 #\1 #\2 #\3 #\4 #\5 #\6 #\7 #\8 #\9 #\+ #\/
     ;;pad 
     #\= )))

;; base64url
(define *decode-url-table*
  ;;    !   "   #   $   %   &   '   (   )   *   +   ,   -   .   /
  #(#f  #f  #f  #f  #f  #f  #f  #f  #f  #f  #f  #f  #f  62  #f  #f  
  ;;0   1   2   3   4   5   6   7   8   9   :   ;   <   =   >   ?
    52  53  54  55  56  57  58  59  60  61  #f  #f  #f  #f  #f  #f
  ;;@   A   B   C   D   E   F   G   H   I   J   K   L   M   N   O
    #f  0   1   2   3   4   5   6   7   8   9   10  11  12  13  14
  ;;P   Q   R   S   T   U   V   W   X   Y   Z   [   \   ]   ^   _
    15  16  17  18  19  20  21  22  23  24  25  #f  #f  #f  #f  63
  ;;`   a   b   c   d   e   f   g   h   i   j   k   l   m   n   o
    #f  26  27  28  29  30  31  32  33  34  35  36  37  38  39  40
  ;;p   q   r   s   t   u   v   w   x   y   z   {   |   }   ~
    41  42  43  44  45  46  47  48  49  50  51  #f  #f  #f  #f  #f
    ))

(define *encode-url-table*
  (vector-map char->integer
     ;;0   1   2   3   4   5   6   7   8   9   10  11  12  13  14  15
   #(#\A #\B #\C #\D #\E #\F #\G #\H #\I #\J #\K #\L #\M #\N #\O #\P
     ;;16  17  18  19  20  21  22  23  24  25  26  27  28  29  30  31
     #\Q #\R #\S #\T #\U #\V #\W #\X #\Y #\Z #\a #\b #\c #\d #\e #\f
     ;;32  33  34  35  36  37  38  39  40  41  42  43  44  45  46  47
     #\g #\h #\i #\j #\k #\l #\m #\n #\o #\p #\q #\r #\s #\t #\u #\v
     ;;48  49  50  51  52  53  54  55  56  57  58  59  60  61  62  63
     #\w #\x #\y #\z #\0 #\1 #\2 #\3 #\4 #\5 #\6 #\7 #\8 #\9 #\- #\_
     ;;pad 
     #\= )))

  
)
