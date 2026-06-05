package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func mustB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func hx(b []byte) string      { return hex.EncodeToString(b) }

func deriveKey(z, salt []byte, info string, length int) []byte {
	ek := make([]byte, length)
	kdf := hkdf.New(sha256.New, z, salt, []byte(info))
	if _, err := kdf.Read(ek); err != nil {
		panic(err)
	}
	return ek
}

func main() {
	// Fixed seeds so the output is reproducible. Not for production use.
	ssk := [32]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}
	csk := [32]byte{
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
		0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
		0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
	}

	spk, _ := curve25519.X25519(ssk[:], curve25519.Basepoint)
	cpk, _ := curve25519.X25519(csk[:], curve25519.Basepoint)

	// Shared secret
	Z, err := curve25519.X25519(csk[:], spk)
	if err != nil {
		panic(err)
	}

	kid := "2026-06"
	aead := "AES-256-GCM"
	issuer := "https://api.example.com"

	// HKDF: salt = epk || spk, with direction-specific info labels.
	salt := append([]byte{}, cpk...)
	salt = append(salt, spk...)
	infoReq := "e2ee/v1:req " + issuer + " " + aead + " " + kid
	infoRes := "e2ee/v1:res " + issuer + " " + aead + " " + kid
	ekReq := deriveKey(Z, salt, infoReq, 32)
	ekRes := deriveKey(Z, salt, infoRes, 32)

	// Request side
	ts := int64(1781006400)
	nid := "3b1c1c2e-2b6a-4a0d-9b6c-2a9f1b6a0e21"
	plaintextReq := []byte(`{"op":"transfer","amount":1000,"to":"acct-42"}`)
	cty := "application/json"

	encField := fmt.Sprintf(
		`"%s"; aead="%s"; epk=:%s:; ts=%d; nid="%s"; cty="%s"`,
		kid, aead, mustB64(cpk), ts, nid, cty,
	)

	// AAD for request: "e2ee/v1:req" SP encryption-field
	aadReq := []byte("e2ee/v1:req " + encField)

	// Fixed nonce for reproducibility.
	nonceReq := []byte{
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	blkReq, _ := aes.NewCipher(ekReq)
	gcmReq, _ := cipher.NewGCM(blkReq)
	ctReq := gcmReq.Seal(nil, nonceReq, plaintextReq, aadReq)
	bodyReq := append([]byte{}, nonceReq...)
	bodyReq = append(bodyReq, ctReq...)

	fmt.Println("=== Inputs ===")
	fmt.Println("server private (ssk) =", hx(ssk[:]))
	fmt.Println("server public  (spk) =", hx(spk))
	fmt.Println("client private (csk) =", hx(csk[:]))
	fmt.Println("client public  (cpk) =", hx(cpk))
	fmt.Println()
	fmt.Println("kid  =", kid)
	fmt.Println("aead =", aead)
	fmt.Println("issuer =", issuer)
	fmt.Println("ts   =", ts)
	fmt.Println("nid  =", nid)
	fmt.Println("cty  =", cty)
	fmt.Println()
	fmt.Println("=== Key Agreement ===")
	fmt.Println("Z   =", hx(Z))
	fmt.Println("salt =", hx(salt))
	fmt.Println("info_req =", infoReq)
	fmt.Println("EK_req  =", hx(ekReq))
	fmt.Println("info_res =", infoRes)
	fmt.Println("EK_res  =", hx(ekRes))
	fmt.Println()
	fmt.Println("=== Request ===")
	fmt.Println("E2EE-Session:", encField)
	fmt.Println("AAD =", string(aadReq))
	fmt.Println("plaintext  =", string(plaintextReq))
	fmt.Println("nonce      =", hx(nonceReq))
	fmt.Println("ciphertext =", hx(ctReq[:len(ctReq)-16]))
	fmt.Println("tag        =", hx(ctReq[len(ctReq)-16:]))
	fmt.Println("body (b64) =", mustB64(bodyReq))

	// Response side
	tsRes := int64(1781006401)
	plaintextRes := []byte(`{"status":"ok","txid":"a1b2c3"}`)

	encFieldRes := fmt.Sprintf(
		`"%s"; aead="%s"; ts=%d; nid="%s"; cty="%s"`,
		kid, aead, tsRes, nid, cty,
	)
	aadRes := []byte("e2ee/v1:res " + encField + " " + encFieldRes)

	nonceRes := []byte{
		0xfe, 0xed, 0xfa, 0xce, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}
	blkRes, _ := aes.NewCipher(ekRes)
	gcmRes, _ := cipher.NewGCM(blkRes)
	ctRes := gcmRes.Seal(nil, nonceRes, plaintextRes, aadRes)
	bodyRes := append([]byte{}, nonceRes...)
	bodyRes = append(bodyRes, ctRes...)

	fmt.Println()
	fmt.Println("=== Response ===")
	fmt.Println("E2EE-Session:", encFieldRes)
	fmt.Println("AAD =", string(aadRes))
	fmt.Println("plaintext  =", string(plaintextRes))
	fmt.Println("nonce      =", hx(nonceRes))
	fmt.Println("ciphertext =", hx(ctRes[:len(ctRes)-16]))
	fmt.Println("tag        =", hx(ctRes[len(ctRes)-16:]))
	fmt.Println("body (b64) =", mustB64(bodyRes))
}
