(ns ring-crypt.core
  "Code taken from ring"
  (:import java.security.SecureRandom
           (javax.crypto Cipher Mac)
           (javax.crypto.spec SecretKeySpec IvParameterSpec)
           org.apache.commons.codec.binary.Base64))

(defn- base64-encode
  "Encode an array of bytes into a base64 encoded string."
  [unencoded]
  (String. (Base64/encodeBase64 unencoded)))

(defn- base64-decode
  "Decode a base64 encoded string into an array of bytes."
  [^String encoded]
  (Base64/decodeBase64 (.getBytes encoded)))

(def ^{:private true
       :doc "Algorithm to seed random numbers."}
  seed-algorithm
  "SHA1PRNG")

(def ^{:private true
       :doc "Algorithm to generate a HMAC."}
  hmac-algorithm
  "HmacSHA256")

(def ^{:private true
       :doc "Type of encryption to use."}
  crypt-type
  "AES")

(def ^{:private true
       :doc "Full algorithm to encrypt data with."}
  crypt-algorithm
  "AES/CBC/PKCS5Padding")

(defn- secure-random-bytes
  "Returns a random byte array of the specified size."
  [size]
  (let [seed (byte-array size)]
    (.nextBytes (SecureRandom/getInstance seed-algorithm) seed)
    seed))

(defn- hmac
  "Generates a Base64 HMAC with the supplied key on a string of data."
  [key data]
  (let [mac (Mac/getInstance hmac-algorithm)]
    (.init mac (SecretKeySpec. key hmac-algorithm))
    (base64-encode (.doFinal mac data))))

(defn- encrypt
  "Encrypt a string with a key."
  [key data]
  (let [cipher     (Cipher/getInstance crypt-algorithm)
        secret-key (SecretKeySpec. key crypt-type)
        iv         (secure-random-bytes (.getBlockSize cipher))]
    (.init cipher Cipher/ENCRYPT_MODE secret-key (IvParameterSpec. iv))
    (->> (.doFinal cipher data)
      (concat iv)
      (byte-array))))

(defn- decrypt
  "Decrypt an array of bytes with a key."
  [key data]
  (let [cipher     (Cipher/getInstance crypt-algorithm)
        secret-key (SecretKeySpec. key crypt-type)
        [iv data]  (split-at (.getBlockSize cipher) data)
        iv-spec    (IvParameterSpec. (byte-array iv))]
    (.init cipher Cipher/DECRYPT_MODE secret-key iv-spec)
    (String. (.doFinal cipher (byte-array data)))))

(defn- get-secret-key
  "Get a valid secret key from a map of options, or create a random one from
  scratch."
  [options]
  (if-let [secret-key (:key options)]
    (if (string? secret-key)
      (.getBytes ^String secret-key)
      secret-key)
    (secure-random-bytes 16)))

(defn seal
  "Seal a Clojure data structure into an encrypted and HMACed string.

key
  The key to encode the string.  Must be 16 bytes.
data
  The data structure to encode."
  [key data]
  (let [data (encrypt key (.getBytes (pr-str data)))]
    (str (base64-encode data) "--" (hmac key data))))

(defn- secure-compare [a b]
  (if (and a b (= (.length a) (.length b)))
      (= 0
         (reduce bit-or
                 (map bit-xor
                      (.getBytes a)
                      (.getBytes b))))
      false))

(defn unseal
  "Retrieve a sealed Clojure data structure from a string

key
  The byte array to use to encode the string.  Must be 16 bytes.
string
  The strin got decode."
  [key ^String string]
  (let [[data mac] (.split string "--")
        data (base64-decode data)]
    (if (secure-compare mac (hmac key data))
        (read-string (decrypt key data)))))
