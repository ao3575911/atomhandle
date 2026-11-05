package main

import (
	"os"

	"github.com/ao3575911/atomhandle/internal/cli"
)

func main() {
	os.Exit(cli.LogMain(os.Args[1:]))
}
