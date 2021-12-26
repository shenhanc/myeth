package client

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func GetClient() *ethclient.Client {
	client, err := ethclient.Dial("http://192.168.1.194:9545")
	if err != nil {
		log.Fatal(err)
	}
	return client
}

func GenPrivateKey() {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)
	fmt.Println(hexutil.Encode(privateKeyBytes)[2:])
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}
	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	// fmt.Println(address)
	bal := GetBalance(address)

	fbalance := new(big.Float)
	fbalance.SetString(bal.String())
	ethValue := new(big.Float).Quo(fbalance, big.NewFloat(math.Pow10(18)))

	evFloat, _ := ethValue.Float32()
	fmt.Println(evFloat)

	if evFloat == 0 {
		fmt.Println("Balance is 0")
	} else {
		fmt.Printf("Balance: %f\n", evFloat)
	}
}

func Load() {
	privKey, err := crypto.LoadECDSA("/home/shenhan/a.a")
	if err != nil {
		log.Fatal(err)
	}
	publicKey := privKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	fmt.Println(address)
}

func GetBalance(pubaddr string) *big.Int {
	client := GetClient()
	account := common.HexToAddress(pubaddr)
	balance, err := client.BalanceAt(context.Background(), account, nil)
	if err != nil {
		log.Fatal(err)
	}
	return balance
}

func GetBalance2(addr common.Address) float32 {
	client := GetClient()
	bal, err := client.BalanceAt(context.Background(), addr, nil)
	if err != nil {
		log.Fatal(err)
	}
	fbalance := new(big.Float)
	fbalance.SetString(bal.String())
	ethValue := new(big.Float).Quo(fbalance, big.NewFloat(math.Pow10(18)))
	evFloat, _ := ethValue.Float32()
	return evFloat
}

func GetPrivKey(addr common.Address, filename, auth string) (*keystore.Key, error) {
	// Load the key from the keystore and decrypt its contents
	keyjson, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	key, err := keystore.DecryptKey(keyjson, auth)
	if err != nil {
		return nil, err
	}
	// Make sure we're really operating on the requested key (no swap attacks)
	if key.Address != addr {
		return nil, fmt.Errorf("key content mismatch: have account %x, want %x", key.Address, addr)
	}
	return key, nil
}
