// sharness-ai, the Go reference implementation: policy hash FILE | policy check FILE.
// The same words and exit codes as the Python CLI for these two commands; nothing else exists yet.
package main

import (
	"fmt"
	"os"

	"github.com/SHarness-AI/SHarness-AI__Go/policy"
)

const usage = `sharness-ai (Go) experiments stage: no SHarness component is built
  policy hash FILE     the one value the person supplies: canonical JSON -> sha256:...
  policy check FILE    the shape of a v0 policy
The standard and its test vectors: https://sharness.ai/code/standards/policy-v0/`

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) != 3 || args[0] != "policy" || (args[1] != "hash" && args[1] != "check") {
		fmt.Println(usage)
		if len(args) == 0 {
			return 0
		}
		return 2
	}
	file := args[2]
	text, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sharness-ai policy: %v\n", err)
		return 1
	}
	pol, err := policy.Parse(text, file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sharness-ai policy: %v\n", err)
		return 1
	}
	if args[1] == "hash" {
		h, err := policy.Hash(pol)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sharness-ai policy: %v\n", err)
			return 1
		}
		fmt.Println(h)
		return 0
	}
	if problems := policy.Check(pol); len(problems) > 0 {
		fmt.Printf("%s: %d problem(s)\n", file, len(problems))
		for _, p := range problems {
			fmt.Printf("  x %s\n", p)
		}
		return 1
	}
	h, _ := policy.Hash(pol)
	fmt.Printf("%s: well-formed v0 policy, id %s: %s; %s\n", file, pol["id"], policy.Summary(pol), h)
	return 0
}
