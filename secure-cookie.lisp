;;;; secure-cookie lisp
;;;;
;;;; This file is part of the hunchentoot-secure-cookie library, released under MIT.
;;;; See file README.org for details.
;;;;
;;;; Author: Gihnius lyj <gihnius@gmail.com>
;;;;
;;;; secure-cookie: encodes and decodes authenticated and optionally encrypted cookie values
;;;;

(defpackage #:hunchentoot-secure-cookie
  (:use #:cl #:hunchentoot #:cl-ppcre)
  ;; not sure why the class symbol cookie not to be exported from the package of hunchentoot.
  (:import-from #:hunchentoot #:cookie)
  (:export #:set-secret-key-base
           #:*random-key*
           #:set-secure-cookie
           #:get-secure-cookie
           #:delete-secure-cookie))

(in-package :hunchentoot-secure-cookie)

;; Need to set this key (string) in order to do encryption/decryption
(defvar *cookie-secret-key-base* ""
  "REQUIRED: The cookie token(string) to make hash for encryption/decryption")
(defvar *old-key-base* "")

;; generate random encrypt key every time
;; but can't verify cookies every time the server app restart.
;; default is nil/false
;; to enhance security, you can set it to t/true
(defvar *random-key* nil)

(defun secure-cookie-p ()
  "Encrypt cookie if token is set"
  (> (length *cookie-secret-key-base*) 0))

(defvar *hkey* nil
  "Hmac hash key")
(defvar *skey* nil
  "AES encrypt key")

;; create random cipher key
;; return: (encrypt-key hmac-key)
;; passphrase: use *cookie-secret-key-base* (string)
;; use ironclad:pbkdf2-hash-password instead
(defun register-key (passphrase)
  (let* ((kdf (ironclad:make-kdf 'ironclad:pbkdf2 :digest 'ironclad:sha256))
         (pass (ironclad:ascii-string-to-byte-array passphrase))
         (salt (if *random-key* (ironclad:make-random-salt 32) pass))
         (digest (ironclad:derive-key kdf pass salt 1 64)))
    (values
     (subseq digest 0 32)
     (subseq digest 32 64))))

;; generate random IV: http://en.wikipedia.org/wiki/Initialization_vector
(defun generate_iv ()
  (ironclad:make-random-salt (ironclad:block-length 'ironclad:aes)))

;; use AES-CBC-256 cipher default
;; return: cipher
;; key: the encrypt-key (bytes array)
(defun get-cipher (key iv)
  (ironclad:make-cipher 'ironclad:aes :key key :mode 'ironclad:cbc :initialization-vector iv))

;; bind *hkey* only once
;; in a running session, if *hkey* reset, cookies from client will not be verified by HMAC.
(defun crypto-init (&optional reset-hkey)
  (when (secure-cookie-p)
    (multiple-value-bind (s h) (register-key *cookie-secret-key-base*)
      (setq *skey* s)
      (if (or reset-hkey (not *hkey*) (not (string= *old-key-base* *cookie-secret-key-base*)))
          (setq *hkey* h)))))

;; the interface to init or change the secret key token.
(defun set-secret-key-base (key &optional reset-hkey)
  "change or init the *cookie-secret-key-base* value"
  (setq *old-key-base* *cookie-secret-key-base*)
  (setq *cookie-secret-key-base* key)
  (crypto-init reset-hkey))

;; base64 encode before concatenate
(defun pack-cookie (name encrypted-value)
  "name|date|value"
  (format nil "~A|~A|~A"
          (cl-base64:string-to-base64-string name)
          (get-universal-time) ; integer
          (cl-base64:usb8-array-to-base64-string encrypted-value)))

;; remove name and append mac digest => "date|value|mac"
(defun pack-signature (cookie-name pack mac-digest)
  (let ((name-len (length (cl-base64:string-to-base64-string cookie-name)))
        (mac-str (cl-base64:usb8-array-to-base64-string mac-digest)))
    (format nil "~A|~A" (subseq pack (1+ name-len)) mac-str)))

;; => "date|value|mac"
;; make sure return the right format
;; restore | by: base64-string -> string
(defun unpack-cookie (val)
  (let* ((dec (cl-base64:base64-string-to-string val))
         (list (split "\\|" dec)))
    (if (and list (eql (length list) 3))
        (values-list list)
        (values "" "" ""))))

;; name: cookie-name (string)
;; value: cookie-value (string)
;; return base64 of encrypted value of "data|value|mac"
(defun encrypt-and-encode (name value)
  (let ((mac (ironclad:make-hmac *hkey* 'ironclad:SHA256))
        (iv (generate_iv))
        (content (babel:string-to-octets value :encoding :utf-8 )))
    (ironclad:encrypt-in-place (get-cipher *skey* iv) content)
    (let* ((new-content (concatenate 'vector iv content)) ; include the IV
           (pack (pack-cookie name new-content)))
      (ironclad:update-hmac mac (babel:string-to-octets pack :encoding :utf-8))
      (cl-base64:string-to-base64-string (pack-signature name pack (ironclad:hmac-digest mac))))))

;; return nil if failed to decrypt/decode/hmac-verify
(defun decode-and-decrypt (name value)
  (multiple-value-bind (ts content hmac) (unpack-cookie value) ; "date|value|mac"
    (let* ((mac (ironclad:make-hmac *hkey* 'ironclad:SHA256))
           (back-pack (format nil "~A|~A|~A"
                              (cl-base64:string-to-base64-string name)
                              ts
                              content)) ; "name|date|value"
           (back-hmac-digest (cl-base64:base64-string-to-usb8-array hmac)))
      ;; Verify hmac
      (ironclad:update-hmac mac (babel:string-to-octets back-pack :encoding :utf-8))
      ;; TODO: also check the ts (get-universal-time) format
      (when (equalp back-hmac-digest (ironclad:hmac-digest mac))
        ;; extract the iv and decrypt
        (let* ((data (cl-base64:base64-string-to-usb8-array content))
               (iv (subseq data 0 (ironclad:block-length 'ironclad:aes)))
               (val (subseq data (ironclad:block-length 'ironclad:aes))))
          (ironclad:decrypt-in-place (get-cipher *skey* iv) val)
          (babel:octets-to-string val :encoding :utf-8))))))

;; set http-only to true in SECURE COOKIE
(defun set-secure-cookie (name &key (value "") max-age expires path domain secure (http-only t) (reply *reply*))
  "set the secure cookie, works like set-cookie in hunchentoot."
  (when (secure-cookie-p)
    (let ((val (handler-case (encrypt-and-encode name value)
                 (condition (c) (values nil (log-message* :warning "Failed to encode or encrypt cookie value! ~S" c))))))
      (set-cookie* (make-instance 'cookie
                                  :name name
                                  :value val
                                  :expires expires
                                  :max-age max-age
                                  :path path
                                  :domain domain
                                  :secure secure
                                  :http-only http-only)
                   reply))))

(defun get-secure-cookie (name &optional (request *request*))
  "get cookie using cookie-in then decode and decrypt, return NIL if failed."
  (let ((cookie-value (cookie-in name request)))
    (when (and (secure-cookie-p) cookie-value (> (length cookie-value) 0))
      (handler-case
          (decode-and-decrypt name cookie-value)
        (condition (c) (values nil (log-message* :warning "Failed to decode or decrypt cookie value! ~S" c)))))))

(defun delete-secure-cookie (name)
  (set-secure-cookie name :value ""))
