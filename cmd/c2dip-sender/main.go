package main

import (
	"os"

	"c2dip/internal/cli"
)

func main() { os.Exit(cli.MainSender(os.Args[1:])) }
