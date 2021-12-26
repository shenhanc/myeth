package client

import (
	"fmt"
	"syscall"

	"golang.org/x/term"
)

func AskPasswordNoConfirm(prompt string) (string, error) {
	fmt.Printf("%s", prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Print("\n")
	if err != nil {
		return "", err
	}
	password := string(bytePassword)
	return password, nil
}

func AskPassword(prompt string) (string, error) {
	fmt.Printf("%s", prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Print("\nType again to confirm: ")
	bytePasswordConfrim, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Print("\n")
	if err != nil {
		return "", err
	}
	password := string(bytePassword)
	passwordConfrim := string(bytePasswordConfrim)
	if password != passwordConfrim {
		return "", fmt.Errorf("passwords do not match")
	}
	return password, nil
}
