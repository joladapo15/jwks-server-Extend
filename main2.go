package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"
)

var db *sql.DB

// JWK represents a single JSON Web Key.
// Kid MUST be a string so the gradebot can unmarshal it correctly.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"` // string, not int
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is the JSON Web Key Set returned by /.well-known/jwks.json
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// base64url encodes a big.Int as a Base64url string with no padding.
func base64url(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

// initDB opens (or creates) the SQLite database and creates the keys table.
func initDB() {
	var err error
	db, err = sql.Open("sqlite", "totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS keys(
			kid INTEGER PRIMARY KEY AUTOINCREMENT,
			key BLOB NOT NULL,
			exp INTEGER NOT NULL
		)`)
	if err != nil {
		log.Fatal(err)
	}
}

// x509Marshal serialises an RSA private key to PKCS#1 DER bytes.
func x509Marshal(key *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(key)
}

// generateKey creates a 2048-bit RSA key and stores it in the DB.
// If expired is true the key is stored with an exp one hour in the past.
func generateKey(expired bool) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("generateKey: %v", err)
		return
	}

	exp := time.Now().Add(time.Hour).Unix()
	if expired {
		exp = time.Now().Add(-time.Hour).Unix()
	}

	if _, err := db.Exec("INSERT INTO keys(key, exp) VALUES(?, ?)", x509Marshal(key), exp); err != nil {
		log.Printf("generateKey insert: %v", err)
	}
}

// seedKeys ensures at least one valid and one expired key exist in the DB.
func seedKeys() {
	now := time.Now().Unix()

	var count int
	db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp > ?", now).Scan(&count)
	if count == 0 {
		generateKey(false)
	}

	db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp <= ?", now).Scan(&count)
	if count == 0 {
		generateKey(true)
	}
}

// getKey fetches a key row from the DB using a parameterised query.
func getKey(expired bool) (int, *rsa.PrivateKey) {
	now := time.Now().Unix()

	var row *sql.Row
	if expired {
		row = db.QueryRow("SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1", now)
	} else {
		row = db.QueryRow("SELECT kid, key FROM keys WHERE exp > ? LIMIT 1", now)
	}

	var kid int
	var keyBytes []byte
	if err := row.Scan(&kid, &keyBytes); err != nil {
		log.Printf("getKey scan: %v", err)
		return 0, nil
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		log.Printf("getKey parse: %v", err)
		return 0, nil
	}
	return kid, key
}

// authHandler issues a signed JWT.
// Authentication is mocked — any request (with or without credentials) gets a token.
func authHandler(w http.ResponseWriter, r *http.Request) {
	expired := r.URL.Query().Has("expired")

	kid, key := getKey(expired)
	if key == nil {
		http.Error(w, "no suitable key found", http.StatusInternalServerError)
		return
	}

	var claims jwt.MapClaims
	if expired {
		// Issue a JWT whose timestamps are in the past
		claims = jwt.MapClaims{
			"sub": "userABC",
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
			"exp": time.Now().Add(-1 * time.Hour).Unix(),
		}
	} else {
		claims = jwt.MapClaims{
			"sub": "userABC",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(5 * time.Minute).Unix(),
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// kid must be a string in the JWT header to match the JWKS
	token.Header["kid"] = fmt.Sprintf("%d", kid)

	signed, err := token.SignedString(key)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": signed})
}

// jwksHandler returns all non-expired public keys as a JWKS.
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	now := time.Now().Unix()

	// Parameterised query — only expose non-expired public keys
	rows, err := db.Query("SELECT kid, key FROM keys WHERE exp > ?", now)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var keys []JWK

	for rows.Next() {
		var kid int
		var keyBytes []byte
		if err := rows.Scan(&kid, &keyBytes); err != nil {
			continue
		}

		key, err := x509.ParsePKCS1PrivateKey(keyBytes)
		if err != nil {
			continue
		}
		pub := key.PublicKey

		keys = append(keys, JWK{
			Kty: "RSA",
			Use: "sig",
			Kid: fmt.Sprintf("%d", kid), // string
			Alg: "RS256",
			N:   base64url(pub.N),
			E:   base64url(big.NewInt(int64(pub.E))),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JWKS{Keys: keys})
}

func main() {
	initDB()
	seedKeys()

	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)

	log.Println("Server running on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
