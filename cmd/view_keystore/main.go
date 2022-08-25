package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/shenhanc/myeth/pkg/client"
)

var (
	flag_keystore string
)

func initFlags() {
	flag.StringVar(&flag_keystore, "keystore", filepath.Join(os.Getenv("HOME"), ".myeth/keystore"), "keystore dir")
	flag.Parse()
}

func main() {
	initFlags()
	fmt.Printf("Using keystore '%s'\n", flag_keystore)
	if pwd, err := client.AskPasswordNoConfirm("Passphrase to access the private key (enter to skip access private key): "); err == nil {
		ks := keystore.NewKeyStore(flag_keystore, keystore.StandardScryptN, keystore.StandardScryptP)
		for _, wallet := range ks.Wallets() {
			// if e := wallet.Open(pwd); e != nil {
			// 	fmt.Printf("Error open wallet, wrong password? (Error: %s)\n", e)
			// 	os.Exit(1)
			// }
			for _, account := range wallet.Accounts() {
				var key *keystore.Key
				var e2 error
				fmt.Printf("Wallet file: %s\n", account.URL.Path)
				fmt.Printf("Publick key: %s\n", account.Address.Hex())
				if len(pwd) > 0 {
					if key, e2 = client.GetPrivKey(account.Address, account.URL.Path, pwd); e2 != nil {
						fmt.Printf("Error unlocking account, wrong passphrase? (Error: %s)\n", e2)
						os.Exit(1)
					}
					fmt.Printf("Private key: %s\n", hexutil.Encode(key.PrivateKey.D.Bytes())[2:])
				} else {
					fmt.Println("Private key: (skipped because passphrase is not entered)")
				}
				fmt.Printf("Balance of %s:\n%f\n", account.Address.Hex(), client.GetBalance2(account.Address))
			}
		}
	}
}
