package main

import (
	"os"

	"c2dip/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }
