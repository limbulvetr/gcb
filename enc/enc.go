package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/limbulvetr/gcb/common"
	"golang.org/x/crypto/ssh"
)

func main() {
	keyFile := flag.String("k", "gcb.pub", "public key file")
	flag.Parse()
	inputFileList := flag.Args()

	pub, err := readPublicKeyFromFile(*keyFile)
	if err != nil {
		panic(err)
	}

	if len(inputFileList) == 0 {
		fmt.Println("Warning: Should provide at least one input file in args.")
	}
	for _, inputFile := range inputFileList {
		err = encryptFile(pub, inputFile)
		if err != nil {
			panic(err)
		}
	}
}

func encryptFile(pub *rsa.PublicKey, inputFile string) error {
	aesKey, err := common.AESRand32()
	if err != nil {
		return err
	}
	encAESKey, err := rsaEnc(pub, aesKey)
	if err != nil {
		return err
	}
	fmt.Println(len(encAESKey), "key len")

	input, err := ioutil.ReadFile(inputFile)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(input), "octets read from file", inputFile)

	encInput, err := common.AESEncWithNonce(aesKey, input)
	if err != nil {
		panic(err)
	}

	payload := append(encAESKey, encInput...)
	encFileName := inputFile + ".gcb"
	err = ioutil.WriteFile(encFileName, payload, 0655)
	if err != nil {
		panic(err)
	}
	fmt.Println("File encryption successful:", encFileName)
	return nil
}

func readPublicKeyFromFile(fileName string) (*rsa.PublicKey, error) {
	keyBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
	if err != nil {
		return nil, err
	}
	parsedCryptoKey := key.(ssh.CryptoPublicKey)
	pubCrypto := parsedCryptoKey.CryptoPublicKey()
	return pubCrypto.(*rsa.PublicKey), nil
}

func rsaEnc(pub *rsa.PublicKey, input []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, input, nil)
}
