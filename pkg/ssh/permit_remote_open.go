package ssh

import (
	"context"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/things-go/go-socks5"
	statute "github.com/things-go/go-socks5/statute"
)

type PermitRemoteOpen struct {
	Domains []string
}

// Allow socks5.WithRule doesn't allow multiple rules, so we need to combine our rules here.
// 1. We only allow `CONNECT` commands, not `BIND` or `ASSOCIATE`.
// 2. We support domain filtering via the new -permit-domains flag.
// We make a best effort to support `-ssh-flag='-o PermitRemoteOpen=mysql.example.com:3306` style as well.
func (p *PermitRemoteOpen) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	// we only allow CONNECT
	if req.Command != statute.CommandConnect {
		return ctx, false
	}

	// no domains specified means accept all
	if len(p.Domains) < 1 {
		return ctx, true
	}

	// lowercase domains so we can compare
	domains := make([]string, len(p.Domains))
	for i, d := range p.Domains {
		domains[i] = strings.ToLower(d)
	}
	host := strings.ToLower(req.RawDestAddr.FQDN)

	if host == "" {
		host = req.RawDestAddr.IP.String()
	}

	if slices.Contains(domains, host) {
		return ctx, true
	}

	// account for ports
	if req.RawDestAddr.Port > 0 {
		host = net.JoinHostPort(host, strconv.Itoa(req.RawDestAddr.Port))
	}

	if slices.Contains(domains, host) {
		return ctx, true
	}

	return ctx, false
}

// MapSSHPermitToSocks maps sshFlags for PermitRemoteOpen to -domains
func MapSSHPermitToSocks(sshFlags []string) (domains []string, err error) {
	for _, f := range sshFlags {
		name, value, err := extractOptionFromFlag(f)
		if err != nil {
			return nil, err
		}
		if name == "PermitRemoteOpen" {
			for domain := range strings.SplitSeq(value, " ") {
				domains = append(domains, domain)
			}
		}
	}
	return domains, nil
}
