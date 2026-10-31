package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/alexedwards/argon2id"
)

func main() {
	password, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	password = strings.TrimRight(password, "\r\n")
	if password == "" {
		fmt.Fprintln(os.Stderr, "usage: the password is read from the first line of stdin")
		os.Exit(2)
	}
	hash, hashError := argon2id.CreateHash(password, argon2id.DefaultParams)
	if hashError != nil {
		fmt.Fprintln(os.Stderr, hashError)
		os.Exit(1)
	}
	fmt.Println(hash)
}
