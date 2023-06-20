package main

import (
	"fmt"
	"os"

	"github.com/anchore/grype/cmd"
)

func main() {
	cli := cmd.NewCli()
	err := cli.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}
}
