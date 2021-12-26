package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/shenhanc78/myeth/pkg/client"
)

var (
	flag_wallet           string
	flag_passphrase       string
	flag_eth_node_address string
	flag_gwei             int64
	flag_recipient        string
)

func initFlags() {
	flag.StringVar(&flag_wallet, "wallet", "", "wallet json file path")
	flag.StringVar(&flag_passphrase, "passphrase", "", "passphrase for the wallet")
	flag.StringVar(&flag_eth_node_address, "eth_node_address", "", "specify eth node address")
	flag.Int64Var(&flag_gwei, "gwei", 0, "specify value to transfer (in gwei)")
	flag.StringVar(&flag_recipient, "recipient", "", "recipient address")
	flag.Parse()

	if flag_wallet == "" {
		fmt.Println("Must specify wallet file to transfer from via --wallet")
		os.Exit(1)
	}

	if flag_recipient == "" {
		fmt.Println("Must specify --recipient")
		os.Exit(1)
	}

	if flag_gwei == 0 {
		fmt.Println("Must specify none zero transfer value via --gwei")
		os.Exit(1)
	}
}

func load_wallet() *keystore.Key {
	var jsblob []byte
	var err error
	if jsblob, err = ioutil.ReadFile(flag_wallet); err != nil {
		fmt.Printf("Error reading wallet file '%s': %s\n", flag_wallet, err)
		os.Exit(1)
	}

	var passphrase string
	if flag_passphrase != "" {
		passphrase = flag_passphrase
	} else {
		if passphrase, err = client.AskPasswordNoConfirm("Wallet passphrase: "); err != nil {
			fmt.Printf("Error: %s\n", err)
			os.Exit(1)
		}
	}
	var key *keystore.Key
	if key, err = keystore.DecryptKey(jsblob, passphrase); err != nil {
		fmt.Printf("Error decrypt (wrong passphrase?): %s\n", err)
		os.Exit(1)
	}
	return key
}

func main() {
	initFlags()

	key := load_wallet()
	publicKey := key.PrivateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
		os.Exit(1)
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	if flag_eth_node_address != "" {
		client.SetEthNodeAddress(flag_eth_node_address)
	}
	var nonce uint64
	var err error
	if nonce, err = client.GetClient().PendingNonceAt(context.Background(), fromAddress); err != nil {
		fmt.Printf("Failed to get nonce: %s\n", err)
		os.Exit(1)
	}

	gwei_unit := big.NewInt(1000000000)
	value_in_gwei := big.NewInt(flag_gwei)
	var value_in_wei big.Int
	value_in_wei.Mul(value_in_gwei, gwei_unit)

	gasLimit := uint64(21000)

	gasPrice, err := client.GetClient().SuggestGasPrice(context.Background())

	fmt.Printf("Suggested gas price: %s\n", gasPrice)

	recipientAddress := common.HexToAddress(flag_recipient)

	var data []byte
	tx := types.NewTransaction(nonce, recipientAddress, &value_in_wei, gasLimit, gasPrice, data)

	chainID, err := client.GetClient().NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), key.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	var buf bytes.Buffer
	signedTx.EncodeRLP(&buf)

	rawTxHex := hex.EncodeToString(buf.Bytes())

	fmt.Printf("Tx content: 0x%s\n", rawTxHex)
}
