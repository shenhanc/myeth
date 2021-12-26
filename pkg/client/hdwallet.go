package client

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"

	bip39 "github.com/tyler-smith/go-bip39"
	bip39wordlist "github.com/tyler-smith/go-bip39/wordlists"
)

func GetEthereumWalletAndDefaultAccountFromMnemonic(mnemonic string) (*hdwallet.Wallet, accounts.Account, error) {
	var err error
	var wallet *hdwallet.Wallet
	var account accounts.Account
	if wallet, err = hdwallet.NewFromMnemonic(mnemonic); err != nil {
		return nil, account, err
	}
	// For Exodus or other single account wallet, this is the default path.
	if hdwallet.DefaultBaseDerivationPath.String() != "m/44'/60'/0'/0/0" {
		fmt.Printf("Internal check error.\n")
		os.Exit(1)
	}
	if account, err = wallet.Derive(hdwallet.DefaultBaseDerivationPath, false); err != nil {
		return nil, accounts.Account{}, err
	}
	return wallet, account, nil
}

func GetEthereumPrivateKeyFromMnemonic(mnemonic string) (*ecdsa.PrivateKey, error) {
	wallet, account, err := GetEthereumWalletAndDefaultAccountFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	return wallet.PrivateKey(account)
}

func GetEthereumPublicKeyFromMnemonic(mnemonic string) (*ecdsa.PublicKey, error) {
	wallet, account, err := GetEthereumWalletAndDefaultAccountFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	return wallet.PublicKey(account)
}

func GetEthereumAddressFromMnemonic(mnemonic string) (common.Address, error) {
	_, account, err := GetEthereumWalletAndDefaultAccountFromMnemonic(mnemonic)
	if err != nil {
		return common.Address{}, err
	}
	return account.Address, nil
}

func CreateWallet(keystore_dir string, wordlist []string, passphrase string) (string, accounts.Account, error) {
	if len(wordlist) == 0 {
		wordlist = bip39wordlist.English
	}
	entropy := make([]byte, 32)
	var err error
	var mnemonic string
	if _, err = rand.Read(entropy); err != nil {
		return "", accounts.Account{}, err
	}
	bip39.SetWordList(wordlist)
	if mnemonic, err = bip39.NewMnemonic(entropy); err != nil {
		return "", accounts.Account{}, err
	}
	var privkey *ecdsa.PrivateKey
	if privkey, err = GetEthereumPrivateKeyFromMnemonic(mnemonic); err != nil {
		return "", accounts.Account{}, err
	}
	// fmt.Printf("Private key: %s\n", hexutil.Encode(privkey.D.Bytes())[2:])
	ks := keystore.NewKeyStore(keystore_dir, keystore.StandardScryptN, keystore.StandardScryptP)
	var new_account accounts.Account
	if new_account, err = ks.ImportECDSA(privkey, passphrase); err != nil {
		return "", accounts.Account{}, err
	}
	return mnemonic, new_account, nil
}

// My signed
// {
//   "address": "0xfccfbe74440f6efe3d8b73988017b16d9bd7dfe7",
//   "msg": "Apple",
//   "sig": "0x9a599aec0de252c3edd9889a48dab1662d6169bcdcc3f993afe2898f4a7f95da417fc04c0ab70638d79fc35e4f0400d124f42668c91d15176f45d3a80e74b9091c",
//   "version": "2"
// }
