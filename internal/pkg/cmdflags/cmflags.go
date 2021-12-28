package cmdflags

import "flag"

var (
	Flag_eth_node_address string
	Flag_wallet           string
	Flag_passphrase       string
)

func Init() {
	flag.StringVar(&Flag_wallet, "wallet", "", "wallet json file path")
	flag.StringVar(&Flag_passphrase, "passphrase", "", "passphrase to unlock wallets")
	flag.StringVar(&Flag_eth_node_address, "eth_node_address", "", "specify eth node address")
}
