package main

import (
	"crypto"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/shenhanc78/myeth/pkg/aesz"
	"github.com/shenhanc78/myeth/pkg/client"
)

const (
	// encrypt each 1MB data
	encrypt_input_size = 1024 * 1024
	encrypt_tag_size   = 16
)

var (
	flag_passphrase string
	flag_encrypt    string
	flag_decrypt    string
	flag_out        string
)

func initFlags() {
	flag.StringVar(&flag_passphrase, "passphrase", "", "passphrase")
	flag.StringVar(&flag_encrypt, "enc", "", "file to be encrypted")
	flag.StringVar(&flag_decrypt, "dec", "", "file to be decrypted")
	flag.StringVar(&flag_out, "out", "", "output file name")
	flag.Parse()

	if flag_encrypt == "" && flag_decrypt == "" {
		log.Fatal("Must specify file name via --enc or --dec.")
	}

	if flag_encrypt != "" && flag_decrypt != "" {
		log.Fatal("Only one of --enc or --dec can be used.")
	}

	if flag_out == "" {
		log.Fatal("Must specify output file name via --out.")
	}
}

func decrypt(passphrase string) error {
	var fin io.ReadCloser
	var fout io.WriteCloser
	var err error
	fout, err = os.OpenFile(flag_out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(0666))
	if err != nil {
		return err
	}
	defer func() {
		if err := fout.Close(); err != nil {
			log.Fatalf(`Error closing output file: "%s"`, flag_out)
		}
	}()
	if fin, err = os.Open(flag_decrypt); err != nil {
		return err
	}
	defer func() {
		if err := fin.Close(); err != nil {
			log.Printf(`Warning: error closing input file "%s"`, flag_decrypt)
		}
	}()
	return aesz.Decipher(passphrase, fin, fout)
}

func encrypt(passphrase string) error {
	var err error
	var fin io.ReadCloser
	fin, err = os.Open(flag_encrypt)
	if err != nil {
		return err
	}
	defer func() {
		if err := fin.Close(); err != nil {
			log.Printf(`Warning: error closing input file "%s"`, flag_encrypt)
		}
	}()

	var fout io.WriteCloser
	fout, err = os.OpenFile(flag_out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(0666))
	if err != nil {
		return err
	}
	defer func() {
		if err := fout.Close(); err != nil {
			log.Fatalf(`Error closing output file: "%s"`, flag_out)
		}
	}()

	return aesz.Encrypt(passphrase, fin, fout)
}

func main() {
	if !crypto.SHA3_256.Available() {
		fmt.Printf("Error: sha3_256 not available on you system.")
		os.Exit(1)
	}
	initFlags()
	var passphrase string = flag_passphrase
	var err error
	if passphrase == "" {
		if flag_encrypt != "" {
			passphrase, err = client.AskPassword("Passphrase to encrypt the file: ")
		} else {
			passphrase, err = client.AskPasswordNoConfirm("Passphrase to decrypt the file: ")
		}
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}
	}

	if passphrase == "" {
		fmt.Println("Passphrase is empty, cannot proceed.")
		os.Exit(1)
	}

	if flag_encrypt != "" {
		err = encrypt(passphrase)
	} else if flag_decrypt != "" {
		err = decrypt(passphrase)
	}

	if err != nil {
		log.Fatal(err)
	}
}
