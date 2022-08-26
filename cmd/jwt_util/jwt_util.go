package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func main() {
	var Flag_secret_file string
	flag.StringVar(&Flag_secret_file, "secret-file", "", "filename that contains 64-character hex secret without 0x")
	flag.Parse()

	if Flag_secret_file == "" {
		return
	}

	fin, err := os.Open(Flag_secret_file)
	if err != nil {
		fmt.Printf("faile to open file: %s: %v\n", Flag_secret_file, err)
		return
	}

	sb := make([]byte, 64)
	if _, err := io.ReadFull(fin, sb); err != nil {
		fmt.Printf("faile to 32 bytes from file: %s: %v\n", Flag_secret_file, err)
		return
	}

	sb_str := string(sb)
	secret, err := hex.DecodeString(sb_str)
	if err != nil {
		fmt.Printf("Invalid file content: %s\n", Flag_secret_file)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		// Required claim for engine API auth. "iat" stands for issued at
		// and it must be a unix timestamp that is +/- 5 seconds from the current
		// timestamp at the moment the server verifies this value.
		"iat": time.Now().Unix(),
	})

	bearer, err := token.SignedString(secret)
	if err != nil {
		fmt.Printf("failed to sign: %s", err)
		return
	}

	fmt.Printf("Bearer %s\n", bearer)

}
