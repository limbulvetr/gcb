package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/limbulvetr/gcb/common"
)

func main() {
	secretFile := flag.String("k", "gcb.gcbsecret", "gcb secret key file")
	flag.Parse()
	inputFileList := flag.Args()

	encSecret, err := ioutil.ReadFile(*secretFile)
	if err != nil {
		panic(err)
	}
	password := common.ReadPassword("Enter dec password... ")
	prv, err := decSecret(encSecret, password)
	if err != nil {
		panic(err)
	}

	if len(inputFileList) == 0 {
		fmt.Println("Warning: Should provide at least one input file in args.")
	}
	for _, inputFile := range inputFileList {
		if !strings.HasSuffix(inputFile, ".gcb") {
			fmt.Println("Unknown file format", inputFile, ": should be a .gcb file. Skipping this.")
			continue
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
		fmt.Println("File decryption successful:", decFileName)
	}

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
