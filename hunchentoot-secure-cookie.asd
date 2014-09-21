(asdf:defsystem #:hunchentoot-secure-cookie
  :serial t
  :depends-on (#:cl-ppcre
               #:hunchentoot
               #:cl-base64
               #:ironclad
               #:babel)
  :components ((:file "secure-cookie")))

(asdf:defsystem #:hunchentoot-secure-cookie-test
  :serial t
  :depends-on (#:drakma #:hunchentoot-secure-cookie #:rt)
  :components ((:file "tests")))
