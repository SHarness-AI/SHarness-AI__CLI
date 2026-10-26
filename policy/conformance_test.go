package policy

// The standard's test vectors: every accept case hashes to the hash the standard gives, every
// refuse case is refused. conformance/vectors.json is a vendored copy; conformance/fetch.sh
// refreshes it from sharness.ai, and CI runs this test against the live copy too
// (SHARNESS_AI_VECTORS names another directory).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type manifest struct {
	Standard string `json:"standard"`
	Version  string `json:"version"`
	Counts   struct{ Accept, Refuse int }
	Cases    []struct {
		Name, File, Kind, Hash, Reason string
	}
}

func TestConformance(t *testing.T) {
	dir := os.Getenv("SHARNESS_AI_VECTORS")
	if dir == "" {
		dir = filepath.Join("..", "conformance")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Standard != "policy" || m.Version != "v0" || len(m.Cases) != m.Counts.Accept+m.Counts.Refuse {
		t.Fatalf("the manifest is not the policy standard at v0: %+v", m.Counts)
	}
	for _, c := range m.Cases {
		c := c
		t.Run(c.Kind+"/"+c.Name, func(t *testing.T) {
			text, err := os.ReadFile(filepath.Join(dir, c.File))
			if err != nil {
				t.Fatal(err)
			}
			pol, err := Parse(text, c.Name)
			var problems []string
			if err != nil {
				problems = []string{err.Error()}
			} else {
				problems = Check(pol)
			}
			if c.Kind == "accept" {
				if len(problems) > 0 {
					t.Fatalf("must be accepted, got %v", problems)
				}
				h, err := Hash(pol)
				if err != nil || h != c.Hash {
					t.Fatalf("hash %s, the standard says %s (%v)", h, c.Hash, err)
				}
			} else if len(problems) == 0 {
				t.Fatalf("must be refused (%s)", c.Reason)
			}
		})
	}
}
