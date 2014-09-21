#|

;; test
(in-package :hunchentoot-secure-cookie)
;; set or change the key
(hunchentoot-secure-cookie:set-cookie-secret-key-base "passphrase")
;; start server
(hunchentoot:start (make-instance 'hunchentoot:easy-acceptor :port 4242))
;; visit http://localhost:4242/set?value=this
(hunchentoot:define-easy-handler (set-cookie-val :uri "/set") (value)
  (setf (hunchentoot:content-type*) "text/plain")
  (hunchentoot-secure-cookie:set-secure-cookie "secure-cookie" :value (if value value "") :max-age (* 3600 24))
  (hunchentoot:set-cookie "unsecure-cookie" :value "test value")
  (format nil "You set cookie: ~A" value))

(hunchentoot:define-easy-handler (get-cookie-val :uri "/get") ()
  (setf (hunchentoot:content-type*) "text/plain")
  (format nil "secure-cookie: ~A~&original encoded cookie: ~A~&unsecure-cookie: ~A~&unsecure-as-secure: ~A"
          (hunchentoot-secure-cookie:get-secure-cookie "secure-cookie")
          (Hunchentoot:cookie-in "secure-cookie")
          (hunchentoot:cookie-in "unsecure-cookie")
          (hunchentoot-secure-cookie:get-secure-cookie "unsecure-cookie")))

|#
