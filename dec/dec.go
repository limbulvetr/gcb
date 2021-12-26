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
	outputFile := flag.String("o", "", "output file, leave blank to print to std")
	flag.Parse()
	inputFileList := flag.Args()

	secret, err := ioutil.ReadFile(*secretFile)
	if err != nil {
		panic(err)
	}
	password := common.ReadPassword("Enter dec password... ")
	prv, err := decSecret(secret, password)
	if err != nil {
		panic(err)
	}

	if len(inputFileList) != 1 {
		fmt.Println("Warning: Should provide EXACTLY ONE input file in args.")
	}
	err = decryptFile(prv, inputFileList[0], *outputFile)
	if err != nil {
		panic(err)
	}

	return
}

func decryptFile(prv *rsa.PrivateKey, inputFile string, outputFile string) error {
	if !strings.HasSuffix(inputFile, ".gcb") {
		fmt.Printf("Unknown file format: [%s] should be a .gcb file, Skipping this.\n", inputFile)
		return nil
	}

	input, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return err
	}
	fmt.Println(len(input), "octets read from file", inputFile)

	encAESKey := input[:256]
	encData := input[256:]

	aesKey, err := rsaDec(prv, encAESKey)
	if err != nil {
		return err
	}

	data, err := common.AESDecWithNonce(aesKey, encData)
	if err != nil {
		return err
	}

	if outputFile == "" {
		fmt.Println(string(data))
		return nil
	}

	err = ioutil.WriteFile(outputFile, data, 0655)
	if err != nil {
		panic(err)
	}
	fmt.Println("File decryption successful:", outputFile)
	return nil
}

func decSecret(secret []byte, password string) (*rsa.PrivateKey, error) {
	aesKey := common.AESGen32([]byte(password))
	prvKeyBytes, err := common.AESDecWithNonce(aesKey, secret)
	if err != nil {
		return nil, err
	}
	prv, err := x509.ParsePKCS1PrivateKey(prvKeyBytes)
	if err != nil {
		return nil, err
	}
	return prv, nil
}

func rsaDec(prv *rsa.PrivateKey, input []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, prv, input, nil)
}
