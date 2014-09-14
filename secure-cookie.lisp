;;;; secure-cookie lisp
;;;;
;;;; This file is part of the hunchentoot-secure-cookie library, released under MIT.
;;;; See file README.org for details.
;;;;
;;;; Author: Gihnius lyj <gihnius@gmail.com>
;;;;

(defpackage :hunchentoot-secure-cookie
  (:use :cl :hunchentoot :cl-ppcre)
  ;; not sure why the class symbol cookie not to be exported from the package of hunchentoot.
  (:import-from :hunchentoot :cookie)
  (:export :*cookie-secret-token*
           :*cookie-secret-cipher-key*
           :set-secure-cookie
           :get-secure-cookie
           :delete-secure-cookie))

(in-package :hunchentoot-secure-cookie)

(defclass secure-cookie (cookie)
  ())

;; Need to set this token(ascii string) in order to do encryption/decryption
(defvar *cookie-secret-token* ""
  "REQUIRED: The secret token(ascii string) to make hash for encryption/decryption")

(defvar *cookie-secret-cipher-key* nil)
;; OPTIONAL: The key to make (AES) cipher, accept 16/24/32 ascii characters length.
(defvar *default-key* (hunchentoot::create-random-string 16))

(defun register-key ()
  (let (key)
    (if *cookie-secret-cipher-key*
        (let ((len (length *cookie-secret-cipher-key*)))
          (cond
            ((>= len 32) (setq key (subseq *cookie-secret-cipher-key* 0 32)))
            ((>= len 24) (setq key (subseq *cookie-secret-cipher-key* 0 24)))
            ((>= len 16) (setq key (subseq *cookie-secret-cipher-key* 0 16)))
            (t (setq key *default-key*))))
        (setq key *default-key*))
    key))

(defun secure-cookie-p ()
  "Encrypt cookie if token is set"
  (> (length *cookie-secret-token*) 0))

(defun get-cipher ()
  (ironclad:make-cipher 'ironclad:aes :key (ironclad:ascii-string-to-byte-array (register-key)) :mode 'ironclad:cbc :initialization-vector (make-array (ironclad:block-length 'ironclad:aes) :initial-element 0 :element-type '(unsigned-byte 8))))

(defun encrypt-and-encode (plain-string)
  (let ((cipher (get-cipher))
        (msg (flexi-streams:string-to-octets plain-string :external-format :utf-8)))
    (ironclad:encrypt-in-place cipher msg)
    (cl-base64:usb8-array-to-base64-string msg)))

(defun decode-and-decrypt (encoded-string)
  (let ((cipher (get-cipher))
        (msg (cl-base64:base64-string-to-usb8-array encoded-string)))
    (ironclad:decrypt-in-place cipher msg)
    (flexi-streams:octets-to-string msg :external-format :utf-8)))

(defun pack-cookie-value (val)
  (format nil "~A|~A"
          (cl-base64:usb8-array-to-base64-string (flexi-streams:string-to-octets val :external-format :utf-8))
          (cl-base64:string-to-base64-string *cookie-secret-token*)))

(defun unpack-cookie-value (val)
  (flexi-streams:octets-to-string (cl-base64:base64-string-to-usb8-array (car (split "\\|" val))) :external-format :utf-8))

(defmethod initialize-instance :after ((cookie secure-cookie) &key)
  "Encode and Encrypt the COOKIE."
  (let ((val (cookie-value cookie)))
    (when (> (length val) 0)
      ;; JS can't read the encrypted cookie, so set http-only to true by default.
      (setf (cookie-http-only cookie) t)
      (setf (cookie-value cookie) (encrypt-and-encode (pack-cookie-value val))))))

(defun set-secure-cookie (name &key (value "") expires max-age path domain secure http-only (reply *reply*) (acceptor *acceptor*))
  "set the secure cookie, works like set-cookie in hunchentoot."
  ;; here to ignore the session-cookie where store the session-id and session-string if you are using hunchentoot:session
  ;; it's because hard to do decryption of session-cookie outside the package of hunchentoot
  (when (string= name (session-cookie-name acceptor))
    (return-from set-secure-cookie))
  (when (secure-cookie-p)
    (set-cookie* (make-instance 'secure-cookie
                                :name name
                                :value value
                                :expires expires
                                :max-age max-age
                                :path path
                                :domain domain
                                :secure secure
                                :http-only http-only)
                 reply)))

(defun get-secure-cookie (name &optional (request *request*) (acceptor *acceptor*))
  "get cookie using cookie-in then decode and decrypt"
  ;; ignore session-cookie in hunchentoot
  (when (string= name (session-cookie-name acceptor))
    (return-from get-secure-cookie))
  (let ((cookie-value (cookie-in name request)))
    (when (and (secure-cookie-p) cookie-value (> (length cookie-value) 0))
      (ignore-errors
        ;; key reset may causes (decrypt) 500 http error
        (unpack-cookie-value (decode-and-decrypt cookie-value))))))

(defun delete-secure-cookie (name)
  (set-secure-cookie name :value ""))


#|
;; test
(in-package :hunchentoot-secure-cookie)
(setq *cookie-secret-token* "passphrase")
;; change hash token
(setq hunchentoot-secure-cookie:*cookie-secret-token* "passphrase")
;; change cipher key
(setq hunchentoot-secure-cookie:*cookie-secret-cipher-key* "1234567890123456")
;; start server
(hunchentoot:start (make-instance 'hunchentoot:easy-acceptor :port 4242))
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
