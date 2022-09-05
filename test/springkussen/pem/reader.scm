#!r6rs
(import (rnrs)
	(springkussen conditions)
	(springkussen pem reader)
	(srfi :64))

(test-begin "PEM reader")

(test-assert (pem-object?
	      (read-pem-object
	       (open-string-input-port
		"-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgVcB/UNPxalR9zDYAjQIf
jojUDiQuGnSJrFEEzZPT/92hRANCAASc7UJtgnF/abqWM60T3XNJEzBv5ez9TdwK
H0M6xpM2q+53wmsN/eYLdgtjgBd3DBmHtPilCkiFICXyaA8z9LkJ
-----END PRIVATE KEY-----"))))

(test-error "Space before preeb"
	    springkussen-condition?
	    (read-pem-object
	     (open-string-input-port
	      "  -----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----")))

(test-error "Space before posteb"
	    springkussen-condition?
	    (read-pem-object
	       (open-string-input-port
		"-----BEGIN PRIVATE KEY-----\n  -----END PRIVATE KEY-----")))

(let ((pem-object (read-pem-object
		   (open-string-input-port
		    "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----"))))
  (test-equal "PRIVATE KEY" (pem-object-label pem-object))
  (test-equal #vu8() (pem-object-content pem-object))
  (test-equal "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n"
	      (pem-object->string pem-object)))

(test-equal "-----BEGIN CUSTOM-----\naGVsbG8=\n-----END CUSTOM-----\n"
	    (pem-object->string
	     (make-pem-object "CUSTOM" (string->utf8 "hello"))))

(test-end)
(exit (test-runner-fail-count (test-runner-current)))
