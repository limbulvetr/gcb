package common

import (
	"fmt"
	"os"

	"github.com/howeyc/gopass"
)

func ReadPassword(prompt string) string {
	fmt.Print(prompt)
	key, err := gopass.GetPasswd()
	if err != nil {
		panic(err)
	}
	return string(key)
}

func AwaitExit(prompt ...interface{}) {
	if len(prompt) != 0 {
		fmt.Println(prompt...)
	}
	fmt.Println("Press Enter to continue...")
	fmt.Scanln()
	os.Exit(-1)
}
