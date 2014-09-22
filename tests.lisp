(defpackage :hunchentoot-secure-cookie.tests
  (:use :cl :hunchentoot :cl-ppcre :hunchentoot-secure-cookie :lisp-unit))

(in-package :hunchentoot-secure-cookie.tests)

(defparameter *ht-acceptor* (make-instance 'hunchentoot:easy-acceptor :port 4343))

(defun cookie-tests-prepare ()
  (hunchentoot:start *ht-acceptor*)
  (hunchentoot-secure-cookie:set-cookie-secret-key-base "passphrase")

  (hunchentoot:define-easy-handler (set-cookie-val :uri "/set") (value)
    (setf (hunchentoot:content-type*) "text/plain")
    (hunchentoot-secure-cookie:set-secure-cookie "secure-cookie" :value (if value value ""))
    (hunchentoot:set-cookie "unsecure-cookie" :value "test value")
    (format nil "You set cookie: ~A" value))

  (hunchentoot:define-easy-handler (get-cookie-val :uri "/get") ()
    (setf (hunchentoot:content-type*) "text/plain")
    (format nil "secure-cookie: ~A~&original encoded cookie: ~A~&unsecure-cookie: ~A~&unsecure-as-secure: ~A"
            (hunchentoot-secure-cookie:get-secure-cookie "secure-cookie")
            (Hunchentoot:cookie-in "secure-cookie")
            (hunchentoot:cookie-in "unsecure-cookie")
            (hunchentoot-secure-cookie:get-secure-cookie "unsecure-cookie"))))

(defun cookie-tests-end ()
  (hunchentoot:stop *ht-acceptor*))

;; do drakma request with cookies
(defmacro with-cookie-request-tests (&body tests)
  `(unwind-protect
        (progn
          (cookie-tests-prepare)
          ,@tests)
     (cookie-tests-end)))
