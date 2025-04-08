package main

import (
	"os"

	"github.com/eliran89c/tag-patrol/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
