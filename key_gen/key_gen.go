package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/howeyc/gopass"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"
)

func main() {
	password := readConsoleInput("Enter enc password...")
	password2 := readConsoleInput("Enter enc password again...")
	if password != password2 {
		fmt.Println("Different passwords, exiting")
		os.Exit(-1)
	}

	prv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	err = outputPubKey(&prv.PublicKey)
	if err != nil {
		panic(err)
	}

	err = outputEncPrvKey(prv, password)
	if err != nil {
		panic(err)
	}
}

func readConsoleInput(prompt string) string {
	fmt.Print(prompt)
	key, err := gopass.GetPasswd()
	if err != nil {
		panic(err)
	}
	return string(key)
}

func outputPubKey(pub *rsa.PublicKey) error {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	return ioutil.WriteFile("gcb.pub", ssh.MarshalAuthorizedKey(sshPub), 0655)
}

func outputEncPrvKey(prv *rsa.PrivateKey, password string) error {
	aesKey := aesGen32([]byte(password))
	encPrvBytes, err := aesEnc(aesKey, x509.MarshalPKCS1PrivateKey(prv))
	if err != nil {
		return err
	}
	return ioutil.WriteFile("gcb_encrypted", encPrvBytes, 0655)
}

func aesEnc(key32 []byte, text []byte) ([]byte, error) {
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

func aesGen32(password []byte) []byte {
	var SALT = []byte("GatherCatalogBabble")
	return pbkdf2.Key(password, SALT, 1, 32, sha256.New)
}
