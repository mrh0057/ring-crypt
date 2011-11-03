(ns ring-crypt.test.core
  (:use [ring-crypt.core] :reload)
  (:use [clojure.test]))

(deftest replace-me
  (let [key (.getBytes "1234567890123456")
        test-obj {:a "b"}
        encoded (seal key test-obj)
        decoded (unseal key encoded)]
    (is (not= test-obj encoded))
    (is (not= encoded decoded))
    (is (= test-obj decoded))))
