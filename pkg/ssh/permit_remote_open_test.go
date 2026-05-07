package ssh

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/things-go/go-socks5"
	statute "github.com/things-go/go-socks5/statute"
)

func TestMapSSHPermitToSocks(t *testing.T) {
	domains, err := MapSSHPermitToSocks([]string{"-o PermitRemoteOpen=foo:9000 bar"})
	assert.NoError(t, err)
	assert.Equal(t, []string{"foo:9000", "bar"}, domains)
}

func TestPermitRemoteOpenAllow(t *testing.T) {
	const exampleCom string = "example.com"
	tests := []struct {
		name    string
		domains []string
		command byte
		addr    *statute.AddrSpec
		allow   bool
	}{
		{
			name:    "rejects non-connect",
			domains: nil,
			command: statute.CommandBind,
			addr:    &statute.AddrSpec{FQDN: exampleCom, Port: 443},
			allow:   false,
		},
		{
			name:    "allows all when no domains configured",
			domains: nil,
			command: statute.CommandConnect,
			addr:    &statute.AddrSpec{FQDN: exampleCom, Port: 443},
			allow:   true,
		},
		{
			name:    "matches fqdn case insensitively",
			domains: []string{exampleCom},
			command: statute.CommandConnect,
			addr:    &statute.AddrSpec{FQDN: "EXAMPLE.COM", Port: 443},
			allow:   true,
		},
		{
			name:    "matches host and port",
			domains: []string{"example.com:443"},
			command: statute.CommandConnect,
			addr:    &statute.AddrSpec{FQDN: exampleCom, Port: 443},
			allow:   true,
		},
		{
			name:    "matches ip when fqdn is empty",
			domains: []string{"10.0.0.5"},
			command: statute.CommandConnect,
			addr:    &statute.AddrSpec{IP: net.ParseIP("10.0.0.5"), Port: 443},
			allow:   true,
		},
		{
			name:    "rejects unmatched destination",
			domains: []string{"example.com:443"},
			command: statute.CommandConnect,
			addr:    &statute.AddrSpec{FQDN: exampleCom, Port: 8443},
			allow:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &PermitRemoteOpen{Domains: tt.domains}
			req := &socks5.Request{
				Request:     statute.Request{Command: tt.command},
				RawDestAddr: tt.addr,
			}

			_, allowed := rule.Allow(context.Background(), req)
			assert.Equal(t, tt.allow, allowed)
		})
	}
}
