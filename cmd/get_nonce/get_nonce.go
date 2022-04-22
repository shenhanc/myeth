package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/shenhanc78/myeth/pkg/client"
)

func main() {
	var Flag_eth_node_address string
	flag.StringVar(&Flag_eth_node_address, "eth_node_address", "", "specify eth node address")
	flag.Parse()
	var nonce uint64
	var err error
	if Flag_eth_node_address != "" {
		client.SetEthNodeAddress(Flag_eth_node_address)
	}
	if nonce, err = client.GetClient().PendingNonceAt(context.Background(), common.HexToAddress(flag.Arg(0))); err != nil {
		fmt.Printf("Failed to get nonce: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("%d\n", nonce)
}
