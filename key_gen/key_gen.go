package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/limbulvetr/gcb/common"
)

func main() {
	outputFile := flag.String("o", "gcb", "output file, will be appended \".pub\" and \".gcbsecret\"")
	flag.Parse()

	password := common.ReadPassword("Enter enc password... ")
	password2 := common.ReadPassword("Enter enc password again... ")
	if password != password2 {
		fmt.Println("Error: Different passwords, exiting")
		os.Exit(-1)
	}

	prv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	pubKeyFile := *outputFile + ".pub"
	err = outputPubKey(&prv.PublicKey, pubKeyFile)
	if err != nil {
		panic(err)
	}

	secretFile := *outputFile + ".gcbsecret"
	err = outputEncPrvKey(prv, password, secretFile)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Key and secret file successfully generated at %s and %s.\n", pubKeyFile, secretFile)
}

func outputPubKey(pub *rsa.PublicKey, fileName string) error {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fileName, ssh.MarshalAuthorizedKey(sshPub), 0655)
}

func outputEncPrvKey(prv *rsa.PrivateKey, password string, fileName string) error {
	aesKey := common.AESGen32([]byte(password))
	encPrvBytes, err := common.AESEncWithNonce(aesKey, x509.MarshalPKCS1PrivateKey(prv))
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fileName, encPrvBytes, 0655)
}
