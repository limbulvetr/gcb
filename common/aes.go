package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

func AESEnc(key32 []byte, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key32)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, text, nil), nil
}

func AESGen32(password []byte) []byte {
	var SALT = []byte("GatherCatalogBabble")
	return pbkdf2.Key(password, SALT, 10000, 32, sha256.New)
}
