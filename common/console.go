package common

import (
	"fmt"

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
