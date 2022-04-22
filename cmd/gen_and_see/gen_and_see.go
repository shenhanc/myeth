package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/shenhanc78/myeth/pkg/client"
)

func main() {
	client.SetEthNodeAddress("http://192.168.1.194:9545")
	for i := 1; i < 1000; i++ {
		privateKey, err := crypto.GenerateKey()
		if err != nil {
			log.Fatal(err)
		}
		privateKeyBytes := crypto.FromECDSA(privateKey)
		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			log.Fatal("error casting public key to ECDSA")
		}
		address := crypto.PubkeyToAddress(*publicKeyECDSA)
		f := client.GetBalance2(address)
		if f > 0 {
			privKeyStr := hexutil.Encode(privateKeyBytes)[2:]
			fmt.Printf("%s has a non zero balance: %f", privKeyStr, f)
			break
		}
	}

	// privKey, err := crypto.HexToECDSA("")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// ks.ImportECDSA(privKey, "")
	// for _, c := range ks.Accounts() {
	// 	if err := ks.Unlock(c, ""); err != nil {
	// 		fmt.Printf("error: %s\n", err)
	// 	}
	// 	fmt.Printf("account: %s\n", c.Address)
	// 	// fmt.Printf("balance: %f\n", client.GetBalance2(c.Address))
	// }

	// if pwd, err := client.AskPasswordNoConfirm(); err == nil {
	// 	ks := keystore.NewKeyStore("/home/shenhan/.ethereum/wallets", keystore.StandardScryptN, keystore.StandardScryptP)
	// 	for _, wallet := range ks.Wallets() {
	// 		// if e := wallet.Open(pwd); e != nil {
	// 		// 	fmt.Printf("Error open wallet, wrong password? (Error: %s)\n", e)
	// 		// 	os.Exit(1)
	// 		// }
	// 		for _, account := range wallet.Accounts() {
	// 			var key *keystore.Key
	// 			var e2 error
	// 			fmt.Printf("Wallet file: %s\n", account.URL.Path)
	// 			fmt.Printf("Publick key: %s\n", account.Address.Hex())
	// 			if len(pwd) > 0 {
	// 				if key, e2 = client.GetPrivKey(account.Address, account.URL.Path, pwd); e2 != nil {
	// 					fmt.Printf("Error unlock account, wrong password? (Error: %s)\n", e2)
	// 					os.Exit(1)
	// 				}
	// 				fmt.Printf("Private key: %s\n", hexutil.Encode(key.PrivateKey.D.Bytes())[2:])
	// 			} else {
	// 				fmt.Println("Private key: (skipped because passphrase is not entered)")
	// 			}
	// 		}
	// 		// fmt.Printf("%s: %f\n", k.Address.Hex(), client.GetBalance2(k.Address))
	// 	}
	// }
}
