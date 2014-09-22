(asdf:defsystem #:hunchentoot-secure-cookie
  :serial t
  :depends-on (#:cl-ppcre
               #:hunchentoot
               #:cl-base64
               #:ironclad
               #:babel)
  :components ((:file "secure-cookie")))

(asdf:defsystem #:hunchentoot-secure-cookie.tests
  :serial t
  :depends-on (#:drakma #:hunchentoot-secure-cookie #:lisp-unit)
  :components ((:file "tests")))
