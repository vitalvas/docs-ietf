package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testIssuer = "https://api.example.com"

type keySetDocument struct {
	Issuer string         `json:"issuer"`
	Keys   []keySetObject `json:"keys"`
}

type keySetObject struct {
	KID         string   `json:"kid"`
	Alg         string   `json:"alg"`
	AEADs       []string `json:"aeads"`
	PublicKey   string   `json:"public_key"`
	Fingerprint string   `json:"fingerprint"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	MaxSkew     int      `json:"max_skew"`
}

func TestHTTPEncryptedRoundTrip(t *testing.T) {
	serverPublic, err := x25519Public(testServerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	handler := httpPrototypeHandler(t, serverPublic)

	keySet := fetchKeySet(t, handler)
	if keySet.Issuer != testIssuer {
		t.Fatalf("issuer mismatch: %s", keySet.Issuer)
	}
	if len(keySet.Keys) != 1 {
		t.Fatalf("expected one key, got %d", len(keySet.Keys))
	}
	if keySet.Keys[0].KID != "2026-06" || keySet.Keys[0].PublicKey != mustB64URL(serverPublic) {
		t.Fatalf("unexpected key set: %+v", keySet.Keys[0])
	}

	clientPublic, clientKeys, err := deriveClientKeys(testClientPrivate, serverPublic, keySet.Issuer, aeadAES256GCM, keySet.Keys[0].KID)
	if err != nil {
		t.Fatal(err)
	}
	reqField := requestField(RequestMetadata{
		KID:          keySet.Keys[0].KID,
		AEAD:         aeadAES256GCM,
		ClientPublic: clientPublic,
		Timestamp:    1781006400,
		NonceID:      "3b1c1c2e-2b6a-4a0d-9b6c-2a9f1b6a0e21",
		ContentType:  "application/json",
	})
	reqBody, err := sealProtected(clientKeys.RequestKey, testNonceRequest, []byte(`{"op":"transfer","amount":1000,"to":"acct-42"}`), requestAAD(reqField))
	if err != nil {
		t.Fatal(err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, "/api/v1/resource", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set("Content-Type", "application/e2ee")
	httpReq.Header.Set("E2EE-Session", reqField)

	httpRes := serveHTTP(handler, httpReq)
	if httpRes.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", httpRes.Code)
	}
	if got := httpRes.Header().Get("Content-Type"); got != "application/e2ee" {
		t.Fatalf("unexpected content type: %s", got)
	}

	resField := httpRes.Header().Get("E2EE-Session")
	if resField == "" {
		t.Fatal("missing response E2EE-Session")
	}
	resBody := httpRes.Body.Bytes()
	plaintext, err := openProtected(clientKeys.ResponseKey, resBody, responseAAD(reqField, resField))
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != `{"status":"ok","txid":"a1b2c3"}` {
		t.Fatalf("unexpected response plaintext: %s", plaintext)
	}
}

func TestHTTPTamperedHeaderFails(t *testing.T) {
	serverPublic, err := x25519Public(testServerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	handler := httpPrototypeHandler(t, serverPublic)

	clientPublic, clientKeys, err := deriveClientKeys(testClientPrivate, serverPublic, testIssuer, aeadAES256GCM, "2026-06")
	if err != nil {
		t.Fatal(err)
	}
	realField := requestField(RequestMetadata{
		KID:          "2026-06",
		AEAD:         aeadAES256GCM,
		ClientPublic: clientPublic,
		Timestamp:    1781006400,
		NonceID:      "3b1c1c2e-2b6a-4a0d-9b6c-2a9f1b6a0e21",
		ContentType:  "application/json",
	})
	body, err := sealProtected(clientKeys.RequestKey, testNonceRequest, []byte(`{"op":"transfer"}`), requestAAD(realField))
	if err != nil {
		t.Fatal(err)
	}
	tamperedField := requestField(RequestMetadata{
		KID:          "2026-06",
		AEAD:         aeadAES256GCM,
		ClientPublic: clientPublic,
		Timestamp:    1781006400,
		NonceID:      "tampered-nid",
		ContentType:  "application/json",
	})

	httpReq, err := http.NewRequest(http.MethodPost, "/api/v1/resource", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set("Content-Type", "application/e2ee")
	httpReq.Header.Set("E2EE-Session", tamperedField)

	httpRes := serveHTTP(handler, httpReq)
	if httpRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", httpRes.Code)
	}
}

func httpPrototypeHandler(t *testing.T, serverPublic []byte) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/encryption-keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(keySetDocument{
			Issuer: testIssuer,
			Keys: []keySetObject{{
				KID:         "2026-06",
				Alg:         "X25519",
				AEADs:       []string{aeadAES256GCM, "AES-128-GCM"},
				PublicKey:   mustB64URL(serverPublic),
				Fingerprint: "qqj_9wO1CyKX9PbhNQj3JA",
				NotBefore:   "2026-06-09T00:00:00Z",
				NotAfter:    "2026-07-09T00:00:00Z",
				MaxSkew:     300,
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	mux.HandleFunc("/api/v1/resource", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Type") != "application/e2ee" {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		reqField := r.Header.Get("E2EE-Session")
		reqMeta, err := parseRequestField(reqField)
		if err != nil {
			http.Error(w, "malformed", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		_, serverKeys, err := deriveServerKeys(testServerPrivate, reqMeta.ClientPublic, testIssuer, reqMeta.AEAD, reqMeta.KID)
		if err != nil {
			http.Error(w, "key agreement failed", http.StatusBadRequest)
			return
		}
		plaintext, err := openProtected(serverKeys.RequestKey, body, requestAAD(reqField))
		if err != nil {
			http.Error(w, "decrypt_failed", http.StatusBadRequest)
			return
		}
		if string(plaintext) != `{"op":"transfer","amount":1000,"to":"acct-42"}` {
			http.Error(w, "unexpected plaintext", http.StatusBadRequest)
			return
		}

		resField := responseField(ResponseMetadata{
			KID:         reqMeta.KID,
			AEAD:        reqMeta.AEAD,
			Timestamp:   1781006401,
			NonceID:     reqMeta.NonceID,
			ContentType: reqMeta.ContentType,
		})
		resBody, err := sealProtected(serverKeys.ResponseKey, testNonceResponse, []byte(`{"status":"ok","txid":"a1b2c3"}`), responseAAD(reqField, resField))
		if err != nil {
			http.Error(w, "encrypt failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/e2ee")
		w.Header().Set("E2EE-Session", resField)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(resBody); err != nil {
			t.Fatal(err)
		}
	})
	return mux
}

func fetchKeySet(t *testing.T, handler http.Handler) keySetDocument {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "/.well-known/encryption-keys", nil)
	if err != nil {
		t.Fatal(err)
	}
	res := serveHTTP(handler, req)
	if res.Code != http.StatusOK {
		t.Fatalf("key discovery failed: %d", res.Code)
	}
	var doc keySetDocument
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func serveHTTP(handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
