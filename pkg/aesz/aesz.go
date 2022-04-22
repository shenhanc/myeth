package aesz

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"
)

const (
	// encrypt each 1MB data
	EncryptInputSize = 1024 * 1024
	EncryptTagSize   = 16
)

func cipherAEAD(passphrase string) (cipher.AEAD, error) {
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

func Encrypt(passphrase string, plainIn io.Reader, encryptedOut io.Writer) error {
	var err error
	var aesGCM cipher.AEAD
	if aesGCM, err = cipherAEAD(passphrase); err != nil {
		return err
	}

	var nonce []byte = make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	if _, err = encryptedOut.Write(nonce); err != nil {
		return err
	}

	var ibuf []byte = make([]byte, EncryptInputSize+EncryptTagSize)
	// encrypted block size is the size of input block + 16 padding bytes.
	fbuf := ibuf[:EncryptInputSize]
	var n int
	for n, err = io.ReadFull(plainIn, fbuf); err == nil; n, err = io.ReadFull(plainIn, fbuf) {
		encrypted_data := aesGCM.Seal(ibuf[:0], nonce, fbuf, nil)
		if nw, ew := encryptedOut.Write(encrypted_data); ew != nil || nw != len(encrypted_data) {
			return fmt.Errorf("error writing encrypted data: %s", ew)
		}
	}
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		if n > 0 {
			encrypted_data := aesGCM.Seal(ibuf[:0], nonce, fbuf[:n], nil)
			if nw, ew := encryptedOut.Write(encrypted_data); ew != nil || nw != len(encrypted_data) {
				return fmt.Errorf("error writing encrypted data: %s", ew)
			}
		}
	}
	return nil
}

func Decipher(passphrase string, encryptedIn io.Reader, decryptedOUt io.Writer) error {
	var err error

	// 1. read nonce
	var aead cipher.AEAD
	if aead, err = cipherAEAD(passphrase); err != nil {
		return nil
	}
	var nonce []byte = make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(encryptedIn, nonce); err != nil {
		return fmt.Errorf("failed to read nonce: %s", err)
	}

	// 2. read each encrypted block
	var bbuf []byte = make([]byte, EncryptInputSize+EncryptTagSize)
	var plain_data []byte
	var n, w int
	var erro, errw error
	for n, err = io.ReadFull(encryptedIn, bbuf); err == nil; n, err = io.ReadFull(encryptedIn, bbuf) {
		if plain_data, erro = aead.Open(bbuf[:0], nonce, bbuf, nil); erro != nil {
			return erro
		}
		if w, errw = decryptedOUt.Write(plain_data); w != len(plain_data) || errw != nil {
			return fmt.Errorf("failed to write decrypted data: %s", errw)
		}
	}
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		if n > 0 {
			if plain_data, erro = aead.Open(bbuf[:0], nonce, bbuf[:n], nil); erro != nil {
				return erro
			}
			if w, errw = decryptedOUt.Write(plain_data); w != len(plain_data) || errw != nil {
				return fmt.Errorf("failed to write decrypted data: %s", errw)
			}
		}
	}
	return nil
}
