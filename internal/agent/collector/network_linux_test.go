package collector

import "testing"

func TestParseAddr(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port uint32
	}{
		{"0100007F:0016", "127.0.0.1", 22},
		{"00000000:1F90", "0.0.0.0", 8080},
		{"00000000000000000000000001000000:01BB", "::1", 443},
		{"0000000000000000FFFF00000100007F:0050", "127.0.0.1", 80},
	}
	for _, c := range cases {
		ip, port := parseAddr(c.in)
		if ip != c.ip || port != c.port {
			t.Errorf("parseAddr(%q) = %s:%d, want %s:%d", c.in, ip, port, c.ip, c.port)
		}
	}
}
