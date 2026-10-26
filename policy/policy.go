// Package policy is Process Behaviour Policy version 0 in Go: parse, check the shape,
// canonicalise, hash. The standard is https://sharness.ai/code/standards/policy-v0/ and its test
// vectors are what this package is tested against. Standard library only.
//
// Where Go and the reference implementation (Python) would differ, the policy is refused rather
// than hashed differently: a number with a fraction or an exponent (read from the text, since
// json.Number keeps the spelling), an integer beyond 2^53-1, a lone surrogate escape (encoding/json
// would silently turn it into U+FFFD, so the raw text is scanned first), a duplicate key.
// Canonical JSON is written by this package, not by encoding/json, which escapes <, > and &
// and always escapes U+2028 and U+2029; the standard keeps them as they are.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	PBPVersion  = 1
	MaxSafeInt  = 1<<53 - 1
	MaxFileSize = 1 << 20
	MaxIDLength = 200
)

var control = regexp.MustCompile(`[\x00-\x1f\x7f]`)

// Policy is a parsed policy: objects are map[string]any, arrays []any, integers int64,
// strings string, booleans bool, null nil.
type Policy = map[string]any

// Parse reads a policy file's text. Refuses: not JSON, not an object, a duplicate key, a number
// with a fraction or an exponent, an integer beyond 2^53-1, a lone surrogate, over a megabyte.
func Parse(text []byte, name string) (Policy, error) {
	if len(text) > MaxFileSize {
		return nil, fmt.Errorf("%s: larger than %d bytes; a policy is a small file", name, MaxFileSize)
	}
	if err := loneSurrogates(text); err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	v, err := decode(dec, "$")
	if err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%s: not JSON (text after the value)", name)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: a policy is a JSON object", name)
	}
	return obj, nil
}

func decode(dec *json.Decoder, where string) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("not JSON (%v)", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '{' {
			obj := map[string]any{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("not JSON (%v)", err)
				}
				key := k.(string)
				if _, dup := obj[key]; dup {
					return nil, fmt.Errorf("duplicate key %q: a policy must say each thing once", key)
				}
				v, err := decode(dec, where+"."+key)
				if err != nil {
					return nil, err
				}
				obj[key] = v
			}
			_, err = dec.Token()
			return obj, err
		}
		arr := []any{}
		for i := 0; dec.More(); i++ {
			v, err := decode(dec, fmt.Sprintf("%s[%d]", where, i))
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		_, err = dec.Token()
		return arr, err
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			return nil, fmt.Errorf("%s: %s: floats are not allowed in a policy (integers only), so the hash is the same in every language", where, s)
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n > MaxSafeInt || n < -MaxSafeInt {
			return nil, fmt.Errorf("%s: integers must stay within ±%d (JavaScript rounds larger ones)", where, MaxSafeInt)
		}
		return n, nil
	default:
		return t, nil // string, bool, nil
	}
}

// loneSurrogates refuses a \uD800-\uDFFF escape that is not half of a valid pair, in the raw text.
func loneSurrogates(text []byte) error {
	s := string(text)
	for i := 0; i+6 <= len(s); i++ {
		if s[i] != '\\' {
			continue
		}
		// count the backslashes that precede this one: an even number means this one escapes
		n := 0
		for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
			n++
		}
		if n%2 == 1 || s[i+1] != 'u' {
			continue
		}
		cp, err := strconv.ParseUint(s[i+2:i+6], 16, 32)
		if err != nil {
			continue
		}
		switch {
		case cp >= 0xD800 && cp <= 0xDBFF:
			if i+12 <= len(s) && s[i+6] == '\\' && s[i+7] == 'u' {
				if lo, err := strconv.ParseUint(s[i+8:i+12], 16, 32); err == nil && lo >= 0xDC00 && lo <= 0xDFFF {
					i += 11
					continue
				}
			}
			return errors.New("string contains a lone surrogate, which has no UTF-8 form")
		case cp >= 0xDC00 && cp <= 0xDFFF:
			return errors.New("string contains a lone surrogate, which has no UTF-8 form")
		}
	}
	return nil
}

// Canonical writes canonical JSON: keys sorted by byte order (code point order for UTF-8, which
// is UTF-16 order for the ASCII keys v0 has), no whitespace, non-ASCII kept as is.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := write(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func write(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case int64:
		if t > MaxSafeInt || t < -MaxSafeInt {
			return fmt.Errorf("integers must stay within ±%d", MaxSafeInt)
		}
		b.WriteString(strconv.FormatInt(t, 10))
	case int:
		return write(b, int64(t))
	case string:
		writeString(b, t)
	case []any:
		b.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := write(b, x); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := write(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unsupported type %T", v)
	}
	return nil
}

// writeString escapes exactly what Python's json.dumps(ensure_ascii=False) escapes: " \ and the
// controls below 0x20 (\b \f \n \r \t by name, the rest as \u00XX). DEL, U+2028, U+2029, <, > and
// & stay as they are.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// Hash is "sha256:" and the hex digest of the canonical bytes.
func Hash(v any) (string, error) {
	c, err := Canonical(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// PathProblem says why p is not acceptable as a policy path, or "". A policy path is absolute,
// normalised (no .., ., // or trailing slash, so it reads as it binds) and printable.
func PathProblem(p any) string {
	s, ok := p.(string)
	if !ok || !strings.HasPrefix(s, "/") {
		return "must be an absolute path"
	}
	if control.MatchString(s) {
		return "contains a control character"
	}
	if s != "/" && (path.Clean(s) != s || strings.HasSuffix(s, "/") || strings.HasPrefix(s, "//")) {
		return fmt.Sprintf("is not normalised (write it as %q)", path.Clean(s))
	}
	return ""
}

func isInt(v any) (int64, bool) { n, ok := v.(int64); return n, ok }

// Check returns the problems with the shape of a v0 policy; empty means well-formed.
func Check(policy Policy) []string {
	var p []string
	if n, ok := isInt(policy["pbp"]); !ok || n != PBPVersion {
		p = append(p, fmt.Sprintf("pbp must be %d", PBPVersion))
	}
	if id, ok := policy["id"].(string); !ok || id == "" {
		p = append(p, "id must be a non-empty string")
	} else if len([]rune(id)) > MaxIDLength || control.MatchString(id) {
		p = append(p, fmt.Sprintf("id must be at most %d printable characters", MaxIDLength))
	}
	if files, ok := policy["files"].(map[string]any); !ok {
		p = append(p, "files must be an object with read, write and exec lists")
	} else {
		for _, k := range []string{"read", "write", "exec"} {
			v, present := files[k]
			if !present {
				continue
			}
			list, ok := v.([]any)
			if !ok {
				p = append(p, fmt.Sprintf("files.%s must be a list of absolute paths", k))
				continue
			}
			for _, x := range list {
				if why := PathProblem(x); why != "" {
					p = append(p, fmt.Sprintf("files.%s: %q %s", k, x, why))
				}
			}
		}
		for k := range files {
			if k != "read" && k != "write" && k != "exec" {
				p = append(p, fmt.Sprintf("files.%s: unknown key", k))
			}
		}
	}
	if net, isNone := policy["network"].(string); !isNone || net != "none" {
		if obj, ok := policy["network"].(map[string]any); !ok {
			p = append(p, `network must be "none" or {"connect_tcp_ports": [...]}`)
		} else {
			ports, ok := obj["connect_tcp_ports"].([]any)
			good := ok
			for _, x := range ports {
				if n, isN := isInt(x); !isN || n <= 0 || n >= 65536 {
					good = false
				}
			}
			if !good {
				p = append(p, "network.connect_tcp_ports must be a list of ports (1-65535)")
			}
			for k := range obj {
				if k != "connect_tcp_ports" {
					p = append(p, fmt.Sprintf("network.%s: unknown key", k))
				}
			}
		}
	}
	proc, _ := policy["process"].(map[string]any)
	if _, present := policy["process"]; present && proc == nil {
		p = append(p, "process.no_new_privs must be true (v0 always sets it)")
	} else {
		if nnp, present := proc["no_new_privs"]; present && nnp != true {
			p = append(p, "process.no_new_privs must be true (v0 always sets it)")
		} else {
			for _, k := range []string{"max_memory_mb", "max_pids"} {
				if v, present := proc[k]; present && v != nil {
					if n, ok := isInt(v); !ok || n < 0 {
						p = append(p, fmt.Sprintf("process.%s must be a non-negative integer", k))
					}
				}
			}
			for k := range proc {
				if k != "no_new_privs" && k != "max_memory_mb" && k != "max_pids" {
					p = append(p, fmt.Sprintf("process.%s: unknown key", k))
				}
			}
		}
	}
	for k := range policy {
		switch k {
		case "pbp", "id", "layer", "files", "network", "process", "notes":
		default:
			p = append(p, k+": unknown key")
		}
	}
	if _, err := Canonical(policy); err != nil {
		p = append(p, err.Error())
	}
	sort.Strings(p)
	return p
}

// Summary is the one-line description the CLIs print after "well-formed".
func Summary(policy Policy) string {
	files, _ := policy["files"].(map[string]any)
	count := func(k string) int { l, _ := files[k].([]any); return len(l) }
	net := "none"
	if obj, ok := policy["network"].(map[string]any); ok {
		ports, _ := Canonical(obj["connect_tcp_ports"])
		net = "tcp connect to ports " + string(ports)
	}
	caps := ""
	if proc, ok := policy["process"].(map[string]any); ok {
		for _, k := range []string{"max_memory_mb", "max_pids"} {
			if v, present := proc[k]; present && v != nil {
				caps += fmt.Sprintf("; %s %v", strings.Replace(k, "max_", "max ", 1), v)
			}
		}
	}
	return fmt.Sprintf("read %d path(s), write %d, exec %d; network %s%s", count("read"), count("write"), count("exec"), net, caps)
}
