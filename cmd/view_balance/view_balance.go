package main

import (
	"flag"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/shenhanc/myeth/pkg/client"
)

func main() {
	var Flag_eth_node_address string
	flag.StringVar(&Flag_eth_node_address, "eth_node_address", "", "specify eth node address")
	flag.Parse()
	if Flag_eth_node_address != "" {
		client.SetEthNodeAddress(Flag_eth_node_address)
	}
	fmt.Println(flag.Arg(0))
	pubaddr := common.HexToAddress(flag.Arg(0))
	balance := client.GetBalance2(pubaddr)
	fmt.Printf("%.8f\n", balance)
}
