#!r6rs
(import (rnrs)
        (springkussen signature)
	(springkussen pem))

(define key-pair (key-pair-factory:generate-key-pair *key-pair-factory:ecdsa*))

(write-pem-object (public-key->pem-object (key-pair-public key-pair)))
(write-pem-object (private-key->pem-object (key-pair-private key-pair)))
