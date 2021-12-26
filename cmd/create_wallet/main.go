package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/accounts"
	bip39wordlist "github.com/tyler-smith/go-bip39/wordlists"

	"github.com/shenhanc78/myeth/pkg/client"
)

var flag_keystore, flag_wordlist, flag_passphrase string

func initFlags() {
	flag.StringVar(&flag_wordlist, "wordlist", "english", "wordlist to use, must be either 'english' or chinese'")
	flag.StringVar(&flag_keystore, "keystore", filepath.Join(os.Getenv("HOME"), ".myeth/keystore"), "keystore dir")
	flag.StringVar(&flag_passphrase, "passphrase", "", "passphrase for the wallet")
	flag.Parse()
}

func main() {
	initFlags()
	var wordlist []string
	if flag_wordlist == "english" {
		wordlist = bip39wordlist.English
	} else if flag_wordlist == "chinese" {
		wordlist = bip39wordlist.ChineseSimplified
	} else {
		fmt.Println("--wordlist only accept \"chinese\" or \"english\".")
		os.Exit(1)
	}
	var err error
	var passphrase string
	if flag_passphrase != "" {
		passphrase = flag_passphrase
	} else {
		if passphrase, err = client.AskPassword("Choose a passphrase for wallet: "); err != nil {
			fmt.Printf("Error: %s\n", err)
			os.Exit(1)
		}
	}
	var mnemonic string
	var new_acc accounts.Account
	if mnemonic, new_acc, err = client.CreateWallet(flag_keystore, wordlist, passphrase); err != nil {
		fmt.Printf("Error create wallet: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Created wallet with address: %s\n", new_acc.Address.Hex())
	fmt.Printf("Mnemonic: %s\n", mnemonic)
	fmt.Println("Wallet private key: [no show]")
	fmt.Printf("Wallet file: %s\n", new_acc.URL.Path)
}
