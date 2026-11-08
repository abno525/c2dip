package main

import (
	"os"

	"c2dip/internal/cli"
	"c2dip/internal/embedded"
)

func main() {
	os.Exit(cli.MainReceiver(os.Args[1:], embedded.APIKey(), embedded.ReceiverBundle()))
}
