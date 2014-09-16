# package hunchentoot-secure-cookie

Package hunchentoot-secure-cookie encodes and decodes authenticated and optionally encrypted cookie values.

Secure cookies can't be forged, because their values are validated using HMAC. When encrypted, the content is also inaccessible to malicious eyes.

## Installation

if using ASDF-2, you can install it to to the ASDF-2 load dir:

```

cd ~/.local/share/common-lisp/source/

git clone git@github.com:gihnius/hunchentoot-secure-cookie.git

LISP> (asdf:load-system :hunchentoot-secure-cookie)

```

Github: https://github.com/gihnius/hunchentoot-secure-cookie

## Usage

API:

```
hunchentoot-secure-cookie:set-cookie-secret-key-base
hunchentoot-secure-cookie:set-secure-cookie
hunchentoot-secure-cookie:get-secure-cookie
hunchentoot-secure-cookie:delete-secure-cookie

;; init the secret key, it is recommended to use a key with 32 or 64 bytes.
(set-cookie-secret-key-base "................")

;; set a cookie value
(set-secure-cookie "cookie-name" :value "something secret...")
;; with more options
(set-secure-cookie "cookie-name" :value "something secret..."
                                 :path "/"
                                 :max-age 86400)

;; get a cookie value
(get-secure-cookie "cookie-name")
;; return => decrypted string

;; delete a cookie
(delete-secure-cookie "cookie-name")

```

Example:

```

;; your app define
(asdf:defsystem #:my-web-app
  :serial t
  :depends-on (#:cl-ppcre
               #:hunchentoot
               #:hunchentoot-secure-cookie
               ...))

;; set the secret token some where
(hunchentoot-secure-cookie:set-cookie-secret-key-base "passphrase...")

;; start hunchentoot server
(hunchentoot:start (make-instance 'hunchentoot:easy-acceptor :port 4242))

;; define your handlers
(hunchentoot:define-easy-handler (set-cookie-val :uri "/set") (value)
  (setf (hunchentoot:content-type*) "text/plain")
  (hunchentoot-secure-cookie:set-secure-cookie "secure-cookie" :value (if value value ""))
  (format nil "You set cookie: ~A" value))

(hunchentoot:define-easy-handler (get-cookie-val :uri "/get") ()
  (setf (hunchentoot:content-type*) "text/plain")
  (format nil "secure-cookie: ~A~&original encoded cookie: ~A"
          (hunchentoot-secure-cookie::get-secure-cookie "secure-cookie")
          (Hunchentoot:cookie-in "secure-cookie")))

;; test set cookie:
;; visit http://localhost:4242/set?value=this
;; test get cookie
;; visit http://localhost:4242/get

```


## TODO

* Implement a SESSION store based on the secured cookie. So can easily to store mulitple values in ONE secure cookie.
In hunchentoot, the built in session stores values in memory and keep the session id by cookie or QueryString, but it's hard to make the builtin session store on the hunchentoot-secure-cookie outside the package of hunchentoot.

* Error handling
