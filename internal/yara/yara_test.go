package yara

import (
	"reflect"
	"strings"
	"testing"
)

const testRules = `
// comment
rule Eicar : test malware {
  meta:
    description = "EICAR test file"
    severity = "low"
  strings:
    $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" nocase
  condition:
    $e and filesize < 1KB
}

private rule IsELF { condition: uint32(0) == 0x464c457f }

rule ElfMiner {
  strings:
    $a = "stratum+tcp://" ascii
    $b = { 78 6D 72 ( 69 | 49 ) [0-2] 67 }
    $c = /donate-level\s*=\s*\d+/i
  condition:
    IsELF and 2 of ($a, $b, $c)
}

rule WideWord {
  strings:
    $w = "evil" wide fullword
  condition:
    #w >= 1 and $w in (0..100)
}

rule AtZero {
  strings:
    $mz = { 4D 5A }
  condition:
    $mz at 0 and not any of ($x*)
  // unreachable
}
`

func TestScan(t *testing.T) {
	// AtZero references $x* which does not exist: compile must fail.
	if _, err := Compile(testRules); err == nil || !strings.Contains(err.Error(), "$x*") {
		t.Fatalf("expected undefined set error, got %v", err)
	}
	rs, err := Compile(strings.Replace(testRules, "not any of ($x*)", "not $mz at 1", 1))
	if err != nil {
		t.Fatal(err)
	}
	if rs.Len() != 5 {
		t.Fatalf("rules = %d", rs.Len())
	}
	cases := []struct {
		data string
		want []string
	}{
		{`X5O!P%@AP[4\PZX54(P^)7CC)7}$eicar-standard-antivirus-test-file!$H+H*`, []string{"Eicar"}},
		{"\x7fELF....stratum+tcp://pool xmrIg", []string{"ElfMiner"}},
		{"\x7fELF.... xmri\x00\x00g DONATE-LEVEL = 5", []string{"ElfMiner"}},
		{"\x7fELF.... stratum+tcp:// only one", nil},
		{"stratum+tcp:// xmrig not an elf", nil},
		{"ab e\x00v\x00i\x00l\x00 cd", []string{"WideWord"}},
		{"ab xe\x00v\x00i\x00l\x00 cd", nil},
		{"MZ\x90\x00", []string{"AtZero"}},
		{"xMZ", nil},
	}
	for _, c := range cases {
		if got := rs.Scan([]byte(c.data)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Scan(%q) = %v, want %v", c.data, got, c.want)
		}
	}
	if m := rs.Rules()[0].Meta["description"]; m != "EICAR test file" {
		t.Errorf("meta = %q", m)
	}
}

func TestGlobal(t *testing.T) {
	rs, err := Compile(`global rule Small { condition: filesize < 10 }
rule Any { strings: $a = "a" condition: $a }`)
	if err != nil {
		t.Fatal(err)
	}
	if got := rs.Scan([]byte("a")); len(got) != 2 {
		t.Errorf("small: %v", got)
	}
	if got := rs.Scan([]byte("aaaaaaaaaaaaaaa")); got != nil {
		t.Errorf("large: %v", got)
	}
}

func TestCompileErrors(t *testing.T) {
	for _, src := range []string{
		`import "pe" rule a { condition: true }`,
		`rule a { condition: $b }`,
		`rule a { strings: $a = { 4D 5 } condition: $a }`,
		`rule a { strings: $a = "x" condition: $a`,
		`rule a { condition: true } rule a { condition: true }`,
		`rule a { condition: for any i in (1..2) : (true) }`,
	} {
		if _, err := Compile(src); err == nil {
			t.Errorf("Compile(%q) succeeded", src)
		}
	}
}
