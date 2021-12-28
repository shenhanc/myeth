package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	sha3 "golang.org/x/crypto/sha3"

	"github.com/shenhanc78/myeth/pkg/client"
)

const (
	// encrypt each 1MB data
	encrypt_input_size = 1024 * 1024
	encrypt_tag_size   = 16
)

var (
	flag_passphrase string
	flag_encrypt    bool
	flag_decrypt    bool
	flag_in         string
	flag_out        string
)

func initFlags() {
	flag.StringVar(&flag_passphrase, "passphrase", "", "passphrase")
	flag.BoolVar(&flag_encrypt, "enc", false, "encrypt mode")
	flag.BoolVar(&flag_decrypt, "dec", false, "decrypt mode")
	flag.StringVar(&flag_in, "in", "", "file to be encrypted")
	flag.StringVar(&flag_out, "out", "", "file to be encrypted")
	flag.Parse()

	if !flag_encrypt && !flag_decrypt {
		fmt.Println("Must specify --enc or --dec.")
		os.Exit(1)
	}

	if flag_in == "" || flag_out == "" {
		fmt.Println("Must specify --in and --out.")
		os.Exit(1)
	}
}

func get_cipher_aead(passphrase string) (cipher.AEAD, error) {
	var sum256 [32]byte = sha3.Sum256([]byte(passphrase))
	var err error
	var block cipher.Block
	if block, err = aes.NewCipher(sum256[:]); err != nil {
		return nil, err
	}
	var aesGCM cipher.AEAD
	if aesGCM, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}
	return aesGCM, nil
}

func decrypt(passphrase string) error {
	var fin io.Reader
	var fout io.Writer
	var err error
	fout, err = os.OpenFile(flag_out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(0666))
	if err != nil {
		return err
	}
	if fin, err = os.Open(flag_in); err != nil {
		return err
	}

	// 1. read nonce
	var aead cipher.AEAD
	if aead, err = get_cipher_aead(passphrase); err != nil {
		return nil
	}
	var nonce []byte = make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(fin, nonce); err != nil {
		return fmt.Errorf("failed to read nonce: %s", err)
	}

	// 2. read each encrypted block
	var bbuf []byte = make([]byte, encrypt_input_size+encrypt_tag_size)
	var plain_data []byte
	var n, w int
	var erro, errw error
	for n, err = io.ReadFull(fin, bbuf); err == nil; n, err = io.ReadFull(fin, bbuf) {
		if plain_data, erro = aead.Open(bbuf[:0], nonce, bbuf, nil); erro != nil {
			return erro
		}
		if w, errw = fout.Write(plain_data); w != len(plain_data) || errw != nil {
			return fmt.Errorf("Failed to write decrypted data: %s", errw)
		}
	}
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		if n > 0 {
			if plain_data, erro = aead.Open(bbuf[:0], nonce, bbuf[:n], nil); erro != nil {
				return erro
			}
			if w, errw = fout.Write(plain_data); w != len(plain_data) || errw != nil {
				return fmt.Errorf("Failed to write decrypted data: %s", errw)
			}
		}
	}
	return nil

}

func encrypt(passphrase string) error {
	var err error
	var aesGCM cipher.AEAD
	if aesGCM, err = get_cipher_aead(passphrase); err != nil {
		return err
	}

	var nonce []byte = make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	var fin io.Reader
	fin, err = os.Open(flag_in)
	if err != nil {
		return err
	}

	var fout io.Writer
	fout, err = os.OpenFile(flag_out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(0666))
	if err != nil {
		return err
	}
	if _, err = fout.Write(nonce); err != nil {
		return err
	}

	var ibuf []byte = make([]byte, encrypt_input_size+encrypt_tag_size)
	// encrypted block size is the size of input block + 16 padding bytes.
	fbuf := ibuf[:encrypt_input_size]
	var n int
	for n, err = io.ReadFull(fin, fbuf); err == nil; n, err = io.ReadFull(fin, fbuf) {
		encrypted_data := aesGCM.Seal(ibuf[:0], nonce, fbuf, nil)
		if nw, ew := fout.Write(encrypted_data); ew != nil || nw != len(encrypted_data) {
			return fmt.Errorf("Error writing encrypted data: %s", ew)
		}
	}
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		if n > 0 {
			encrypted_data := aesGCM.Seal(ibuf[:0], nonce, fbuf[:n], nil)
			if nw, ew := fout.Write(encrypted_data); ew != nil || nw != len(encrypted_data) {
				return fmt.Errorf("Error writing encrypted data: %s", ew)
			}
		}
	}
	return nil
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
		if flag_encrypt {
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

	if flag_encrypt {
		err = encrypt(passphrase)
	} else if flag_decrypt {
		err = decrypt(passphrase)
	}

	if err != nil {
		log.Fatal(err)
	}
}
