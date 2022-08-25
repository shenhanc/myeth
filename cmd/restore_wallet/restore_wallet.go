package main

import (
	"bufio"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/shenhanc/myeth/pkg/client"
	"github.com/tyler-smith/go-bip39"
	bip39wordlist "github.com/tyler-smith/go-bip39/wordlists"
)

var (
	flag_wordlist      string
	flag_keystore      string
	flag_mnemonic_file string
	flag_passphrase    string
)

func initFlags() {
	flag.StringVar(&flag_wordlist, "wordlist", "english", "wordlist to use, must be either 'english' or chinese'")
	flag.StringVar(&flag_mnemonic_file, "mnemonic_file", "", "mnemonic that restores the wallet")
	flag.StringVar(&flag_keystore, "keystore", filepath.Join(os.Getenv("HOME"), ".myeth/keystore"), "keystore dir")
	flag.StringVar(&flag_passphrase, "passphrase", "", "passphrase for the new restored wallet")
	flag.Parse()

	if len(flag_mnemonic_file) == 0 {
		fmt.Printf("Must specify --mnemonic_file\n")
		os.Exit(1)
	}
	fmt.Printf("Using wordlist \"%s\" (changeabe via --wordlist chinese|english)\n", flag_wordlist)
}

func readMnemonicFile(file string) (string, error) {
	var fp *os.File
	var err error
	if fp, err = os.Open(file); err != nil {
		return "", err
	}
	var mnemonics []string = make([]string, 0, 24)
	var scanner *bufio.Scanner = bufio.NewScanner(fp)
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() && len(mnemonics) <= 24 {
		mnemonics = append(mnemonics, scanner.Text())
	}
	if err = scanner.Err(); err != nil {
		return "", err
	}
	if n := len(mnemonics); !(12 <= n && n <= 24 && (n-12)%3 == 0) {
		return "", fmt.Errorf("invalid number of mnemonics: %d", n)
	}
	return strings.Join(mnemonics, " "), err
}

func main() {
	var err error
	initFlags()
	var mnemonic string
	if mnemonic, err = readMnemonicFile(flag_mnemonic_file); err != nil {
		fmt.Printf("Error reading mnemonic file \"%s\": %s\n", flag_mnemonic_file, err)
		return
	}

	var wallet *hdwallet.Wallet
	var account accounts.Account

	var wordlist []string
	if flag_wordlist == "english" {
		wordlist = bip39wordlist.English
	} else if flag_wordlist == "chinese" {
		wordlist = bip39wordlist.ChineseSimplified
	} else {
		fmt.Println("--wordlist only accept \"chinese\" or \"english\".")
		os.Exit(1)
	}
	bip39.SetWordList(wordlist)

	if wallet, account, err = client.GetEthereumWalletAndDefaultAccountFromMnemonic(mnemonic); err != nil {
		fmt.Printf("Failed to restore from mnemonic: %s\n", err)
		os.Exit(1)
	}
	var addressHex string
	if addressHex, err = wallet.AddressHex(account); err != nil {
		fmt.Printf("Error get public key from account: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Address: %s\n", addressHex)
	var privkeyHexStr string
	if privkeyHexStr, err = wallet.PrivateKeyHex(account); err != nil {
		fmt.Printf("Error get private key from account: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Private key: %s\n", privkeyHexStr)

	var ks *keystore.KeyStore = keystore.NewKeyStore(flag_keystore, keystore.StandardScryptN, keystore.StandardScryptP)
	if ks == nil {
		fmt.Println("Failed to init keystore.")
		os.Exit(1)
	}

	var privkey *ecdsa.PrivateKey
	if privkey, err = wallet.PrivateKey(account); err != nil {
		fmt.Printf("Failed to get private key: %s\n", err)
		os.Exit(1)
	}

	var passphrase string
	if flag_passphrase != "" {
		passphrase = flag_passphrase
	} else {
		if passphrase, err = client.AskPassword("New passphrase for the restored wallet: "); err != nil {
			fmt.Printf("failed: %s\n", err)
			os.Exit(1)
		}
	}

	if passphrase == "" {
		fmt.Println("Empty passphrase, aborted.")
		os.Exit(1)
	}

	var restored_account accounts.Account
	if restored_account, err = ks.ImportECDSA(privkey, passphrase); err != nil {
		fmt.Printf("Failed to import: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Restored wallet into file: %s\n", restored_account.URL.Path)
}
