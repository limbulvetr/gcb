package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"flag"
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

func main() {
	keyFile := flag.String("k", "gcb.pub", "public key file")
	flag.Parse()
	inputFileList := flag.Args()

	key, err := readKeyFromFile(*keyFile)
	if err != nil {
		panic(err)
	}

	if len(inputFileList) == 0 {
		fmt.Println("Warning: Should provide at least one input file in args.")
	}
	for _, inputFile := range inputFileList {
		input, err := ioutil.ReadFile(inputFile)
		if err != nil {
			panic(err)
		}
		fmt.Println(len(input), "octets read from file", inputFile)

		enc, err := enc(key, input)
		if err != nil {
			panic(err)
		}

		encFileName := inputFile + ".gcb"
		err = ioutil.WriteFile(encFileName, enc, 0655)
		if err != nil {
			panic(err)
		}
		fmt.Println("File encryption successful:", encFileName)
	}

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
