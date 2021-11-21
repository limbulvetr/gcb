package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/limbulvetr/gcb/common"
)

func main() {
	if len(os.Args) != 2 {
		common.AwaitExit("Unknown command: Requires exactly 1 args: name of the file to decrypt.")
	}
	inputFile := os.Args[1]
	if !strings.HasSuffix(inputFile, ".gcb") {
		common.AwaitExit("Unknown file format: should be a .gcb file.")
	}

	encSecret, err := ioutil.ReadFile("gcb.gcbsecret")
	if err != nil {
		panic(err)
	}
	password := common.ReadPassword("Enter dec password... ")
	prv, err := decSecret(encSecret, password)
	if err != nil {
		panic(err)
	}

	input, err := ioutil.ReadFile(inputFile)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(input), "octets read from file", inputFile)

	dec, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, prv, input, nil)
	if err != nil {
		panic(err)
	}

	decFileName := inputFile + "dec"
	err = ioutil.WriteFile(decFileName, dec, 0655)
	if err != nil {
		panic(err)
	}

	common.Await("File decryption successful:", decFileName)
	return
}

func decSecret(encSecret []byte, password string) (*rsa.PrivateKey, error) {
	aesKey := common.AESGen32([]byte(password))
	prvKeyBytes, err := common.AESDecWithNonce(aesKey, encSecret)
	if err != nil {
		return nil, err
	}
	prv, err := x509.ParsePKCS1PrivateKey(prvKeyBytes)
	if err != nil {
		return nil, err
	}
	return prv, nil
}
