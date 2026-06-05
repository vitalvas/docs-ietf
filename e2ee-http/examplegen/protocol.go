package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	aeadAES256GCM = "AES-256-GCM"
	labelRequest  = "e2ee/v1:req"
	labelResponse = "e2ee/v1:res"
)

var (
	errInvalidKeyLength = errors.New("invalid X25519 key length")
	errInvalidBody      = errors.New("protected body must be nonce || ciphertext || tag")
	errInvalidNonce     = errors.New("AES-GCM nonce must be 12 octets")
)

type DirectionKeys struct {
	Shared       []byte
	Salt         []byte
	InfoRequest  string
	InfoResponse string
	RequestKey   []byte
	ResponseKey  []byte
}

type RequestMetadata struct {
	KID          string
	AEAD         string
	ClientPublic []byte
	Timestamp    int64
	NonceID      string
	ContentType  string
}

type ResponseMetadata struct {
	KID         string
	AEAD        string
	Timestamp   int64
	NonceID     string
	ContentType string
}

func x25519Public(private []byte) ([]byte, error) {
	if len(private) != 32 {
		return nil, errInvalidKeyLength
	}
	return curve25519.X25519(private, curve25519.Basepoint)
}

func deriveClientKeys(clientPrivate, serverPublic []byte, issuer, aead, kid string) ([]byte, DirectionKeys, error) {
	clientPublic, err := x25519Public(clientPrivate)
	if err != nil {
		return nil, DirectionKeys{}, err
	}
	shared, err := curve25519.X25519(clientPrivate, serverPublic)
	if err != nil {
		return nil, DirectionKeys{}, err
	}
	keys, err := deriveDirectionKeys(shared, clientPublic, serverPublic, issuer, aead, kid)
	return clientPublic, keys, err
}

func deriveServerKeys(serverPrivate, clientPublic []byte, issuer, aead, kid string) ([]byte, DirectionKeys, error) {
	serverPublic, err := x25519Public(serverPrivate)
	if err != nil {
		return nil, DirectionKeys{}, err
	}
	shared, err := curve25519.X25519(serverPrivate, clientPublic)
	if err != nil {
		return nil, DirectionKeys{}, err
	}
	keys, err := deriveDirectionKeys(shared, clientPublic, serverPublic, issuer, aead, kid)
	return serverPublic, keys, err
}

func deriveDirectionKeys(shared, clientPublic, serverPublic []byte, issuer, aead, kid string) (DirectionKeys, error) {
	if len(shared) != 32 || len(clientPublic) != 32 || len(serverPublic) != 32 {
		return DirectionKeys{}, errInvalidKeyLength
	}
	keyLen, err := aeadKeyLength(aead)
	if err != nil {
		return DirectionKeys{}, err
	}
	salt := append([]byte{}, clientPublic...)
	salt = append(salt, serverPublic...)
	infoReq := labelRequest + " " + issuer + " " + aead + " " + kid
	infoRes := labelResponse + " " + issuer + " " + aead + " " + kid
	return DirectionKeys{
		Shared:       append([]byte{}, shared...),
		Salt:         salt,
		InfoRequest:  infoReq,
		InfoResponse: infoRes,
		RequestKey:   hkdfSHA256(shared, salt, infoReq, keyLen),
		ResponseKey:  hkdfSHA256(shared, salt, infoRes, keyLen),
	}, nil
}

func aeadKeyLength(aead string) (int, error) {
	switch aead {
	case "AES-128-GCM":
		return 16, nil
	case "AES-192-GCM":
		return 24, nil
	case "AES-256-GCM":
		return 32, nil
	default:
		return 0, fmt.Errorf("unsupported AEAD %q", aead)
	}
}

func hkdfSHA256(shared, salt []byte, info string, length int) []byte {
	key := make([]byte, length)
	kdf := hkdf.New(sha256.New, shared, salt, []byte(info))
	if _, err := kdf.Read(key); err != nil {
		panic(err)
	}
	return key
}

func requestField(meta RequestMetadata) string {
	field := fmt.Sprintf(
		`"%s"; aead="%s"; epk=:%s:; ts=%d; nid="%s"`,
		meta.KID, meta.AEAD, mustB64(meta.ClientPublic), meta.Timestamp, meta.NonceID,
	)
	if meta.ContentType != "" {
		field += fmt.Sprintf(`; cty="%s"`, meta.ContentType)
	}
	return field
}

func responseField(meta ResponseMetadata) string {
	field := fmt.Sprintf(
		`"%s"; aead="%s"; ts=%d; nid="%s"`,
		meta.KID, meta.AEAD, meta.Timestamp, meta.NonceID,
	)
	if meta.ContentType != "" {
		field += fmt.Sprintf(`; cty="%s"`, meta.ContentType)
	}
	return field
}

func requestAAD(field string) []byte {
	return []byte(labelRequest + " " + field)
}

func responseAAD(requestField, responseField string) []byte {
	return []byte(labelResponse + " " + requestField + " " + responseField)
}

func sealProtected(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, errInvalidNonce
	}
	gcm, err := gcmForKey(key)
	if err != nil {
		return nil, err
	}
	body := append([]byte{}, nonce...)
	return append(body, gcm.Seal(nil, nonce, plaintext, aad)...), nil
}

func openProtected(key, body, aad []byte) ([]byte, error) {
	if len(body) < 28 {
		return nil, errInvalidBody
	}
	gcm, err := gcmForKey(key)
	if err != nil {
		return nil, err
	}
	nonce := body[:12]
	ciphertextAndTag := body[12:]
	return gcm.Open(nil, nonce, ciphertextAndTag, aad)
}

func gcmForKey(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func splitProtectedBody(body []byte) (nonce, ciphertext, tag []byte, err error) {
	if len(body) < 28 {
		return nil, nil, nil, errInvalidBody
	}
	nonce = body[:12]
	ciphertextAndTag := body[12:]
	tagStart := len(ciphertextAndTag) - 16
	return nonce, ciphertextAndTag[:tagStart], ciphertextAndTag[tagStart:], nil
}

func parseRequestField(field string) (RequestMetadata, error) {
	parts := strings.Split(field, "; ")
	if len(parts) < 5 {
		return RequestMetadata{}, errors.New("missing request field parameters")
	}
	meta := RequestMetadata{KID: strings.Trim(parts[0], `"`)}
	for _, part := range parts[1:] {
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			return RequestMetadata{}, fmt.Errorf("malformed parameter %q", part)
		}
		switch name {
		case "aead":
			meta.AEAD = strings.Trim(value, `"`)
		case "epk":
			value = strings.TrimPrefix(strings.TrimSuffix(value, ":"), ":")
			clientPublic, err := base64StdDecode(value)
			if err != nil {
				return RequestMetadata{}, err
			}
			meta.ClientPublic = clientPublic
		case "ts":
			var ts int64
			if _, err := fmt.Sscanf(value, "%d", &ts); err != nil {
				return RequestMetadata{}, err
			}
			meta.Timestamp = ts
		case "nid":
			meta.NonceID = strings.Trim(value, `"`)
		case "cty":
			meta.ContentType = strings.Trim(value, `"`)
		}
	}
	if len(meta.ClientPublic) != 32 {
		return RequestMetadata{}, errInvalidKeyLength
	}
	return meta, nil
}

func base64StdDecode(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func mustB64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
