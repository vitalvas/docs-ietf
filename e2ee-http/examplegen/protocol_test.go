package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var (
	testServerPrivate = mustHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	testClientPrivate = mustHex("a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0")
	testNonceRequest  = mustHex("deadbeef0000000000000001")
	testNonceResponse = mustHex("feedface0000000000000002")
)

func TestWorkedExampleVectors(t *testing.T) {
	serverPublic, err := x25519Public(testServerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientKeys, err := deriveClientKeys(
		testClientPrivate,
		serverPublic,
		"https://api.example.com",
		aeadAES256GCM,
		"2026-06",
	)
	if err != nil {
		t.Fatal(err)
	}

	assertHex(t, "server public", serverPublic, "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c")
	assertHex(t, "client public", clientPublic, "ad438bfae31f6c093d61d4339255ea798092c9fadd07b97827f4b0ae9dee7c1c")
	assertHex(t, "shared secret", clientKeys.Shared, "1eadf045f970f3619aa3a82d3ce461d68ee42839f0563ff052d8db20bf927d29")
	assertHex(t, "request key", clientKeys.RequestKey, "88927bb69c7fce5a26b88ccf3b8638c5e876080eae5349c7a014787e80382f81")
	assertHex(t, "response key", clientKeys.ResponseKey, "2784f1a637499c327e97ad56a0a199b950680c41e57597cea41a220233304a8b")

	reqMeta := RequestMetadata{
		KID:          "2026-06",
		AEAD:         aeadAES256GCM,
		ClientPublic: clientPublic,
		Timestamp:    1781006400,
		NonceID:      "3b1c1c2e-2b6a-4a0d-9b6c-2a9f1b6a0e21",
		ContentType:  "application/json",
	}
	reqField := requestField(reqMeta)
	reqBody, err := sealProtected(
		clientKeys.RequestKey,
		testNonceRequest,
		[]byte(`{"op":"transfer","amount":1000,"to":"acct-42"}`),
		requestAAD(reqField),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, reqCiphertext, reqTag, err := splitProtectedBody(reqBody)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "request ciphertext", reqCiphertext, "a6b3551bec16e7866943502146d893b2baa8bc6a4ef76712f7e4febcb576c82141551464b46eb0f096750ed69020")
	assertHex(t, "request tag", reqTag, "4cc3c77e4c463d111f81bf6cf83f08d5")

	_, serverKeys, err := deriveServerKeys(
		testServerPrivate,
		clientPublic,
		"https://api.example.com",
		aeadAES256GCM,
		"2026-06",
	)
	if err != nil {
		t.Fatal(err)
	}
	plaintextReq, err := openProtected(serverKeys.RequestKey, reqBody, requestAAD(reqField))
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintextReq) != `{"op":"transfer","amount":1000,"to":"acct-42"}` {
		t.Fatalf("request plaintext mismatch: %s", plaintextReq)
	}

	resMeta := ResponseMetadata{
		KID:         "2026-06",
		AEAD:        aeadAES256GCM,
		Timestamp:   1781006401,
		NonceID:     "3b1c1c2e-2b6a-4a0d-9b6c-2a9f1b6a0e21",
		ContentType: "application/json",
	}
	resField := responseField(resMeta)
	resBody, err := sealProtected(
		serverKeys.ResponseKey,
		testNonceResponse,
		[]byte(`{"status":"ok","txid":"a1b2c3"}`),
		responseAAD(reqField, resField),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, resCiphertext, resTag, err := splitProtectedBody(resBody)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "response ciphertext", resCiphertext, "f111c0a217756b5f967108e32ce392d62f4de9380b2267c53b81cc4679bc59")
	assertHex(t, "response tag", resTag, "5b64d39058d1bb23e2cec5f9c69880e1")

	plaintextRes, err := openProtected(clientKeys.ResponseKey, resBody, responseAAD(reqField, resField))
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintextRes) != `{"status":"ok","txid":"a1b2c3"}` {
		t.Fatalf("response plaintext mismatch: %s", plaintextRes)
	}
}

func TestTamperedAADFailsAuthentication(t *testing.T) {
	serverPublic, err := x25519Public(testServerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientKeys, err := deriveClientKeys(
		testClientPrivate,
		serverPublic,
		"https://api.example.com",
		aeadAES256GCM,
		"2026-06",
	)
	if err != nil {
		t.Fatal(err)
	}

	field := requestField(RequestMetadata{
		KID:          "2026-06",
		AEAD:         aeadAES256GCM,
		ClientPublic: clientPublic,
		Timestamp:    1781006400,
		NonceID:      "3b1c1c2e-2b6a-4a0d-9b6c-2a9f1b6a0e21",
		ContentType:  "application/json",
	})
	body, err := sealProtected(clientKeys.RequestKey, testNonceRequest, []byte(`{"ok":true}`), requestAAD(field))
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
	if _, err := openProtected(clientKeys.RequestKey, body, requestAAD(tamperedField)); err == nil {
		t.Fatal("expected tampered AAD to fail authentication")
	}
}

func TestParseRequestField(t *testing.T) {
	clientPublic, err := x25519Public(testClientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	field := requestField(RequestMetadata{
		KID:          "2026-06",
		AEAD:         aeadAES256GCM,
		ClientPublic: clientPublic,
		Timestamp:    1781006400,
		NonceID:      "3b1c1c2e-2b6a-4a0d-9b6c-2a9f1b6a0e21",
		ContentType:  "application/json",
	})
	got, err := parseRequestField(field)
	if err != nil {
		t.Fatal(err)
	}
	if got.KID != "2026-06" || got.AEAD != aeadAES256GCM || got.Timestamp != 1781006400 ||
		got.NonceID != "3b1c1c2e-2b6a-4a0d-9b6c-2a9f1b6a0e21" || got.ContentType != "application/json" {
		t.Fatalf("parsed metadata mismatch: %+v", got)
	}
	if !bytes.Equal(got.ClientPublic, clientPublic) {
		t.Fatalf("parsed client public mismatch: %x", got.ClientPublic)
	}
}

func mustHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}

func assertHex(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Fatalf("%s mismatch:\n got %s\nwant %s", name, hex.EncodeToString(got), want)
	}
}
