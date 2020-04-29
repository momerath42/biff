(ns biff.auth
  (:require
    [crux.api :as crux]
    [ring.middleware.anti-forgery :as anti-forgery]
    [biff.util :as bu]
    [byte-streams :as bs]
    [crypto.random :as random]
    [trident.util :as u]
    [clojure.string :as str]
    [cemerick.url :as url]
    [byte-transforms :as bt]))

(defn get-key [{:keys [biff/node biff/db k]}]
  (or (get (crux/entity db :biff.auth/keys) k)
    (doto (bs/to-string (bt/encode (random/bytes 16) :base64))
      (#(crux/submit-tx
          node
          [[:crux.tx/put
            {:crux.db/id :biff.auth/keys
             k %}]])))))

(defn signin-token [jwt-key email]
  (bu/encode-jwt
    {:iss "biff"
     :iat (u/now)
     :exp (u/add-seconds (u/now) (* 60 30))
     :email email}
    {:secret jwt-key
     :alg :HS256}))

(defn signin-link [{:keys [email url] :as env}]
  (let [email (str/trim email)
        jwt-key (get-key (assoc env :k :jwt-key))
        jwt (signin-token jwt-key email)]
    (-> url
      url/url
      (assoc :query {:token jwt})
      str)))

(defn send-signin-link [{:keys [params/email biff.auth/send-email biff/base-url template location]
                         :as env}]
  (let [link (signin-link (assoc env
                            :email email
                            :url (str base-url "/api/signin")))]
    (send-email {:to email
                 :template template
                 :data {:biff.auth/link link}})
    {:status 302
     :headers/Location location}))

(defn get-uid [{:keys [biff/node biff/db email]}]
  (or (ffirst
        (crux/q db
          {:find '[e]
           :args [{'input-email email}]
           :where '[[e :email email]
                    [(biff.util/email= email input-email)]]}))
    (doto (java.util.UUID/randomUUID)
      (#(crux/submit-tx
          node
          [[:crux.tx/put
            {:crux.db/id {:user/id %}
             :user/id %
             :user/email email}]])))))

(defn signin [{:keys [params/token session]
               :biff.auth/keys [on-signin on-signin-fail]
               :as env}]
  (if-some [email (-> token
                    (bu/decode-jwt {:secret (get-key (assoc env :k :jwt-key))
                                    :alg :HS256})
                    u/catchall
                    :email)]
    (let [uid (get-uid (assoc env :email email))]
      {:status 302
       :headers/Location on-signin
       :cookies/csrf {:path "/"
                      :value (force anti-forgery/*anti-forgery-token*)}
       :session (assoc session :uid uid)})
    {:status 302
     :headers/Location on-signin-fail}))

(defn signout [{:keys [biff.auth/on-signout]}]
  {:status 302
   :headers/Location on-signout
   :cookies/ring-session {:value "" :max-age 0}
   :cookies/csrf {:value "" :max-age 0}
   :session nil})

(defn signed-in? [req]
  {:status (if (-> req :session/uid some?)
             200
             403)})

(defn route [{:biff.auth/keys [on-signup on-signin-request] :as sys}]
  ["/api"
   ["/signup" {:post #(send-signin-link (assoc %
                                          :template :biff.auth/signup
                                          :location (or on-signup on-signin-request)))
               :name ::signup}]
   ["/signin-request" {:post #(send-signin-link (assoc %
                                                  :template :biff.auth/signin
                                                  :location on-signin-request))
                       :name ::signin-request}]
   ["/signin" {:get signin
               :name ::signin
               :middleware [anti-forgery/wrap-anti-forgery]}]
   ["/signout" {:get signout
                :name ::signout}]
   ["/signed-in" {:get signed-in?
                  :name ::signed-in}]])
