;;;; secure-cookie lisp
;;;;
;;;; This file is part of the hunchentoot-secure-cookie library, released under MIT.
;;;; See file README.org for details.
;;;;
;;;; Author: Gihnius lyj <gihnius@gmail.com>
;;;;

(defpackage :hunchentoot-secure-cookie
  (:use :cl :hunchentoot)
  ;; not sure why the class symbol cookie not to be exported from the package of hunchentoot.
  (:import-from :hunchentoot :cookie)
  (:export :*cookie-secret-token*
           :set-secure-cookie))

(in-package :hunchentoot-secure-cookie)

(defclass secure-cookie (cookie)
  ())

;; Need to set this token in order to do encryption/decryption
(defvar *cookie-secret-token* ""
  "The secret token to make cipher for encryption/decryption")

(defun secure-cookie-p ()
  "Encrypt cookie if token is set"
  (> (length *cookie-secret-token*) 0))

(defun get-cipher (key)
  (ironclad:make-cipher :blowfish :mode :ecb :key (ironclad:ascii-string-to-byte-array key)))

(defun encrypt-and-encode (plain-string key)
  (let ((cipher (get-cipher key))
        (msg (babel:string-to-octets plain-string)))
    (ironclad:encrypt-in-place cipher msg)
    (cl-base64:string-to-base64-string (ironclad:byte-array-to-hex-string msg))))

(defun decode-and-decrypt (encoded-string key)
  (let ((cipher (get-cipher key))
        (msg (ironclad:hex-string-to-byte-array (cl-base64:base64-string-to-string encoded-string))))
    (ironclad:decrypt-in-place cipher msg)
    (babel:octets-to-string msg)))

(defmethod initialize-instance :after ((cookie secure-cookie) &key)
  "Encode and Encrypt the COOKIE."
  (let ((val (cookie-value cookie)))
    (when (and (secure-cookie-p) (> (length val) 0))
      ;; JS can't read the encrypted cookie, so set http-only to true by default.
      (setf (cookie-http-only cookie) t)
      (setf (cookie-value cookie) (encrypt-and-encode val *cookie-secret-token*)))))

(defun set-secure-cookie (name &key (value "") expires max-age path domain secure http-only (reply *reply*) (acceptor *acceptor*))
  "set the secure cookie, works like set-cookie in hunchentoot."
  ;; here to ignore the session-cookie where store the session-id and session-string if you are using hunchentoot:session
  ;; it's because hard to do decryption of session-cookie outside the package of hunchentoot
  (when (string= name (session-cookie-name acceptor))
    (return-from set-secure-cookie))
  (set-cookie* (make-instance 'secure-cookie
                              :name name
                              :value value
                              :expires expires
                              :max-age max-age
                              :path path
                              :domain domain
                              :secure secure
                              :http-only http-only)
               reply))

(defun get-secure-cookie (name &optional (request *request*) (acceptor *acceptor*))
  "get cookie using cookie-in then decode and decrypt"
  ;; ignore session-cookie in hunchentoot
  (when (string= name (session-cookie-name acceptor))
    (return-from get-secure-cookie))
  (let ((cookie (cookie-in name request)))
    (when (and cookie (> (length cookie) 0))
      (decode-and-decrypt cookie *cookie-secret-token*))))

#|
;; visit http://localhost:4242/cookie?value=this cookie value
(hunchentoot:define-easy-handler (cookie :uri "/cookie") (value)
  (setf (hunchentoot:content-type*) "text/plain")
  (hunchentoot-secure-cookie:set-secure-cookie "secure-cookie" :value (if value value ""))
  ;; original session works too
  (setf (hunchentoot:session-value :session) "hunchentoot session")
  (format nil "secure-cookie: ~A~&hunchentoot-session: ~A"
          (hunchentoot-secure-cookie::get-secure-cookie "secure-cookie")
          (hunchentoot:session-value :session)))
|#
