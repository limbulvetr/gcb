package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/howeyc/gopass"
	"golang.org/x/crypto/ssh"

	"github.com/limbulvetr/gcb/common"
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
	aesKey := common.AESGen32([]byte(password))
	encPrvBytes, err := common.AESEnc(aesKey, x509.MarshalPKCS1PrivateKey(prv))
	if err != nil {
		return err
	}
	return ioutil.WriteFile("gcb_secret", encPrvBytes, 0655)
}
