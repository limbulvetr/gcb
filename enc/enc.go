package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/limbulvetr/gcb/common"
)

func main() {
	if len(os.Args) != 2 {
		common.AwaitExit("Unknown command: Requires exactly 1 args: name of the file to encrypt.")
	}

	key, err := readKeyFromFile("gcb.pub")
	if err != nil {
		panic(err)
	}

	inputFile := os.Args[1]
	input, err := ioutil.ReadFile(inputFile)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(input), "octets read from file", inputFile)

	enc, err := enc(key, input)
	encFileName := inputFile + ".gcb"
	err = ioutil.WriteFile(encFileName, enc, 0655)
	if err != nil {
		panic(err)
	}

	common.AwaitExit("File encryption successful:", encFileName)
	return
}

func readKeyFromFile(fileName string) (ssh.PublicKey, error) {
	keyBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func enc(key ssh.PublicKey, input []byte) ([]byte, error) {
	parsedCryptoKey := key.(ssh.CryptoPublicKey)
	pubCrypto := parsedCryptoKey.CryptoPublicKey()
	pub := pubCrypto.(*rsa.PublicKey)

	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, input, nil)
}
