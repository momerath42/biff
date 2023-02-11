(ns com.biffweb.impl.auth
  (:require [com.biffweb.impl.misc :as bmisc]
            [com.biffweb.impl.rum :as brum]
            [com.biffweb.impl.time :as btime]
            [com.biffweb.impl.util :as butil]
            [com.biffweb.impl.xtdb :as bxt]
            [clj-http.client :as http]
            [clojure.string :as str]
            [rum.core :as rum]
            [xtdb.api :as xt]))

(defn passed-recaptcha? [{:keys [biff/secret biff.recaptcha/threshold params]
                          :or {threshold 0.5}}]
  (or (nil? (secret :recaptcha/secret-key))
      (let [{:keys [success score]}
            (:body
             (http/post "https://www.google.com/recaptcha/api/siteverify"
                        {:form-params {:secret (secret :recaptcha/secret-key)
                                       :response (:g-recaptcha-response params)}
                         :as :json}))]
        (and success (or (nil? score) (<= threshold score))))))

(defn new-signin-code [length]
  (let [rng (java.security.SecureRandom/getInstanceStrong)]
    (format (str "%0" length "d")
            (.nextInt rng (dec (int (Math/pow 10 length)))))))

(defn email-valid? [ctx email]
  (and email (re-matches #".+@.+\..+" email)))

(defn make-signup-link [{:keys [biff/base-url biff/secret anti-forgery-token]} email]
  (str base-url "/auth/verify-link/"
       (bmisc/jwt-encrypt
        {:intent "signup"
         :email email
         :exp-in (* 60 60)
         :state (butil/sha256 anti-forgery-token)}
        (secret :biff/jwt-secret))))

(defn send-signup-link! [{:keys [biff.auth/email-validator
                                 biff/db
                                 biff/send-email
                                 params]
                          :as ctx}]
  (let [email (butil/normalize-email (:email params))
        url (make-signup-link ctx email)]
    (cond
     (not (passed-recaptcha? ctx))
     {:success false :error "recaptcha"}

     (not (email-validator ctx email))
     {:success false :error "invalid-email"}

     (not (send-email ctx
                      {:template :signup-link
                       :to email
                       :url url
                       :user-exists (some? (bxt/lookup-id db :user/email email))}))
     {:success false :error "send-failed"}

     :else
     {:success true :email email})))

(defn verify-signup-link [{:keys [biff.auth/check-state
                                  biff/secret
                                  path-params
                                  params
                                  anti-forgery-token]}]
  (let [{:keys [intent email state]} (-> (merge params path-params)
                                         :token
                                         (bmisc/jwt-decrypt (secret :biff/jwt-secret)))
        valid-state (= state (butil/sha256 anti-forgery-token))
        valid-email (= email (:email params))]
    (cond
     (not= intent "signup")
     {:success false :error "invalid-link"}

     (or (not check-state) valid-state valid-email)
     {:success true :email email}

     (some? (:email params))
     {:success false :error "invalid-email"}

     :else
     {:success false :error "invalid-state"})))

(defn send-signin-code! [{:keys [biff/db biff/send-email params] :as ctx}]
  (let [email (butil/normalize-email (:email params))
        user-id (bxt/lookup-id db :user/email email)
        code (new-signin-code 6)]
    (cond
     (not (passed-recaptcha? ctx))
     {:success false :error "recaptcha"}

     (nil? user-id)
     {:success false :error "no-user"}

     (not (send-email ctx
                      {:template :signin-code
                       :to email
                       :code code}))
     {:success false :error "send-failed"}

     :else
     {:success true :user-id user-id :code code})))

;;; HANDLERS -------------------------------------------------------------------

(defn signup-handler [{:keys [biff.auth/single-opt-in
                              biff.auth/new-user-tx
                              biff/db
                              params]
                       :as ctx}]
  (let [{:keys [success error email]} (send-signup-link! ctx)
        user-id (bxt/lookup-id db :user/email email)]
    (when (and success single-opt-in (not user-id))
      (bxt/submit-tx ctx (new-user-tx ctx email)))
    {:status 303
     :headers {"location" (if success
                            (str "/welcome?email=" (:email params))
                            (str "/?error=" error))}}))

(defn verify-signup-handler [{:keys [biff.auth/app-path
                                     biff.auth/new-user-tx
                                     biff.xtdb/node
                                     session
                                     params
                                     path-params]
                              :as req}]
  (let [{:keys [success error email]} (verify-signup-link req)
        get-user-id #(bxt/lookup-id (xt/db node) :user/email email)
        existing-user-id (when success (get-user-id))
        token (:token (merge params path-params))]
    (when (and success (not existing-user-id))
      (bxt/submit-tx req
        (new-user-tx req email)))
    {:status 303
     :headers {"location" (cond
                           success
                           app-path

                           (= error "invalid-state")
                           (str "/signup/link?token=" token)

                           (= error "invalid-email")
                           (str "/signup/link?error=incorrect-email&token=" token)

                           :else
                           "/?error=invalid-link")}
     :session (cond-> session
                success (assoc :uid (or existing-user-id (get-user-id))))}))

(defn signin-handler [{:keys [params] :as ctx}]
  (let [{:keys [success error user-id code]} (send-signin-code! ctx)]
    (when success
      (bxt/submit-tx ctx
        [{:db/doc-type :biff.auth/code
          :db.op/upsert {:biff.auth.code/user user-id}
          :biff.auth.code/code code
          :biff.auth.code/created-at :db/now
          :biff.auth.code/failed-attempts 0}]))
    {:status 303
     :headers {"location" (if success
                            (str "/signin/code?email=" (:email params))
                            (str "/signin?error=" error))}}))

(defn verify-signin-handler [{:keys [biff.auth/app-path
                                     biff/db
                                     params
                                     session]
                              :as req}]
  (let [email (butil/normalize-email (:email params))
        code (-> (bxt/lookup db '[{:biff.auth.code/_user [*]}] :user/email email)
                 :biff.auth.code/_user
                 first)
        success (and (passed-recaptcha? req)
                     (some? code)
                     (< (:biff.auth.code/failed-attempts code) 3)
                     (not (btime/elapsed? (:biff.auth.code/created-at code) :now 3 :minutes))
                     (= (:code params) (:biff.auth.code/code code)))
        tx (cond
            success
            [[::xt/delete (:xt/id code)]]

            (and (not success)
                 (some? code)
                 (< (:biff.auth.code/failed-attempts code) 3))
            [{:db/doc-type :biff.auth/code
              :db/op :update
              :xt/id (:xt/id code)
              :biff.auth.code/failed-attempts [:db/add 1]}])]
    (bxt/submit-tx req tx)
    (if success
      {:status 303
       :headers {"location" app-path}
       :session (assoc session :uid (:biff.auth.code/user code))}
      {:status 303
       :headers {"location" (str "/signin/code?error=invalid-code&email=" email)}})))

(defn signout [{:keys [session]}]
  {:status 303
   :headers {"location" "/"}
   :session (dissoc session :uid)})

;;; ----------------------------------------------------------------------------

(defn new-user-tx [ctx email]
  [{:db/doc-type :user
    :db.op/upsert {:user/email email}
    :user/joined-at :db/now}])

(def default-options
  #:biff.auth{:app-path "/app"
              :check-state true
              :new-user-tx new-user-tx
              :single-opt-in false
              :email-validator email-valid?})

(defn wrap-options [handler options]
  (fn [req]
    (handler (merge options req))))

(defn plugin [options]
  {:schema {:biff.auth.code/id :uuid
            :biff.auth/code [:map {:closed true}
                             [:xt/id :biff.auth.code/id]
                             [:biff.auth.code/user :user/id]
                             [:biff.auth.code/code :string]
                             [:biff.auth.code/created-at inst?]
                             [:biff.auth.code/failed-attempts integer?]]}
   :routes [["/auth" {:middleware [[wrap-options (merge default-options options)]]}
             ["/signup"             {:post signup-handler}]
             ["/verify-link/:token" {:get verify-signup-handler}]
             ["/verify-link"        {:post verify-signup-handler}]
             ["/signin"             {:post signin-handler}]
             ["/verify-code"        {:post verify-signin-handler}]
             ["/signout"            {:post signout}]]]})

;;; FRONTEND HELPERS -----------------------------------------------------------

(def recaptcha-disclosure
  [:div {:style {:font-size "0.75rem"
                 :line-height "1rem"
                 :color "#4b5563"}}
   "This site is protected by reCAPTCHA and the Google "
   [:a {:href "https://policies.google.com/privacy"
        :target "_blank"
        :style {:text-decoration "underline"}}
    "Privacy Policy"] " and "
   [:a {:href "https://policies.google.com/terms"
        :target "_blank"
        :style {:text-decoration "underline"}}
    "Terms of Service"] " apply."])

(defn recaptcha-callback [fn-name form-id]
  [:script
   (brum/unsafe
    (str "function " fn-name "(token) { "
         "document.getElementById('" form-id "').submit();"
         "}"))])
