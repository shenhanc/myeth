package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/shenhanc78/myeth/pkg/client"
)

var (
	flag_wallet       string
	flag_passphrase   string
	flag_show_balance bool
)

func initFlags() {
	flag.StringVar(&flag_wallet, "wallet", "", "wallet json file path")
	flag.StringVar(&flag_passphrase, "passphrase", "", "passphrase for the wallet")
	flag.BoolVar(&flag_show_balance, "show_balance", false, "show wallet balance (need network access)")
	flag.Parse()
	if flag_wallet == "" {
		fmt.Printf("Must specify --wallet\n")
		os.Exit(1)
	}
}

func main() {
	initFlags()
	var jsblob []byte
	var err error
	if jsblob, err = ioutil.ReadFile(flag_wallet); err != nil {
		fmt.Printf("Error reading wallet file '%s': %s\n", flag_wallet, err)
		os.Exit(1)
	}
	var passphrase string = ""
	if !flag_show_balance {
		if flag_passphrase != "" {
			passphrase = flag_passphrase
		} else {
			if passphrase, err = client.AskPasswordNoConfirm("Wallet passphrase: "); err != nil {
				fmt.Printf("Error: %s\n", err)
				os.Exit(1)
			}
		}
	}
	if passphrase != "" {
		var key *keystore.Key
		if key, err = keystore.DecryptKey(jsblob, passphrase); err != nil {
			fmt.Printf("Error decrypt (wrong passphrase?): %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("Address: %s\n", key.Address.Hex())
		fmt.Printf("Private key: %s\n", hexutil.Encode(key.PrivateKey.D.Bytes())[2:])
	} else {
		m := make(map[string]interface{})
		if err := json.Unmarshal(jsblob, &m); err != nil {
			fmt.Printf("Invalid json wallet file: \"%s\": %s\n", flag_wallet, err)
			os.Exit(1)
		}
		fmt.Printf("Address: 0x%s\n", m["address"])
		if flag_show_balance {
			balance := client.GetBalance2(common.HexToAddress(m["address"].(string)))
			fmt.Printf("Balance: %.6f\n", balance)
		}
	}
}
