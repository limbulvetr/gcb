package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/limbulvetr/gcb/common"
)

func main() {
	password := common.ReadPassword("Enter enc password... ")
	password2 := common.ReadPassword("Enter enc password again... ")
	if password != password2 {
		common.AwaitInput("Different passwords, exiting")
		os.Exit(-1)
	}

	prv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	err = outputPubKey(&prv.PublicKey, "gcb.pub")
	if err != nil {
		panic(err)
	}

	err = outputEncPrvKey(prv, password, "gcb.gcbsecret")
	if err != nil {
		panic(err)
	}

	common.AwaitInput("Key and secret file successfully generated.")
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
	encPrvBytes, err := common.AESEnc(aesKey, x509.MarshalPKCS1PrivateKey(prv))
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fileName, encPrvBytes, 0655)
}
