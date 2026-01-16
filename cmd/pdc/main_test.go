package main

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateURLs(t *testing.T) {
	tests := []struct {
		name            string
		cluster         string
		domain          string
		newRegionFormat bool
		apiFQDN         string
		gatewayFQDN     string
		wantAPI         string
		wantGW          string
	}{
		// Old format tests (default behavior)
		{
			name:            "old format - default domain",
			cluster:         "some-cluster",
			domain:          "grafana.net",
			newRegionFormat: false,
			wantAPI:         "https://private-datasource-connect-api-some-cluster.grafana.net",
			wantGW:          "private-datasource-connect-some-cluster.grafana.net",
		},
		{
			name:            "old format - custom domain",
			cluster:         "some-cluster",
			domain:          "some-domain.net",
			newRegionFormat: false,
			wantAPI:         "https://private-datasource-connect-api-some-cluster.some-domain.net",
			wantGW:          "private-datasource-connect-some-cluster.some-domain.net",
		},
		// New format tests
		{
			name:            "new format - default domain",
			cluster:         "some-cluster",
			domain:          "grafana.net",
			newRegionFormat: true,
			wantAPI:         "https://private-datasource-connect-api.some-cluster.grafana.net",
			wantGW:          "private-datasource-connect.some-cluster.grafana.net",
		},
		{
			name:            "new format - custom domain",
			cluster:         "some-cluster",
			domain:          "some-domain.net",
			newRegionFormat: true,
			wantAPI:         "https://private-datasource-connect-api.some-cluster.some-domain.net",
			wantGW:          "private-datasource-connect.some-cluster.some-domain.net",
		},
		// Custom FQDN precedence tests
		{
			name:            "custom api-fqdn overrides format",
			cluster:         "some-cluster",
			domain:          "some-domain.net",
			newRegionFormat: true,
			apiFQDN:         "custom-api.example.com",
			wantAPI:         "https://custom-api.example.com",
			wantGW:          "private-datasource-connect.some-cluster.some-domain.net",
		},
		{
			name:            "custom gateway-fqdn overrides format",
			cluster:         "some-cluster",
			domain:          "some-domain.net",
			newRegionFormat: true,
			gatewayFQDN:     "custom-gateway.example.com",
			wantAPI:         "https://private-datasource-connect-api.some-cluster.some-domain.net",
			wantGW:          "custom-gateway.example.com",
		},
		{
			name:            "both custom FQDNs override format",
			cluster:         "some-cluster",
			domain:          "some-domain.net",
			newRegionFormat: true,
			apiFQDN:         "custom-api.example.com",
			gatewayFQDN:     "custom-gateway.example.com",
			wantAPI:         "https://custom-api.example.com",
			wantGW:          "custom-gateway.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &mainFlags{
				Cluster:         tt.cluster,
				Domain:          tt.domain,
				NewRegionFormat: tt.newRegionFormat,
				APIFQDN:         tt.apiFQDN,
				GatewayFQDN:     tt.gatewayFQDN,
			}

			apiURL, gatewayURL, err := createURLs(cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAPI, apiURL.String())
			assert.Equal(t, tt.wantGW, gatewayURL.String())
		})
	}
}

func TestNewRegionFormatEnvVar(t *testing.T) {
	tests := []struct {
		name        string
		envValue    string
		flagValue   string
		wantEnabled bool
	}{
		{
			name:        "env var true enables new format",
			envValue:    "true",
			wantEnabled: true,
		},
		{
			name:        "env var 1 enables new format",
			envValue:    "1",
			wantEnabled: true,
		},
		{
			name:        "env var false uses old format",
			envValue:    "false",
			wantEnabled: false,
		},
		{
			name:        "no env var uses old format",
			envValue:    "",
			wantEnabled: false,
		},
		{
			name:        "flag overrides env var",
			envValue:    "true",
			flagValue:   "false",
			wantEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean environment
			t.Setenv("PDC_NEW_REGION_FORMAT", tt.envValue)

			mf := &mainFlags{}
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			mf.RegisterFlags(fs)

			// Parse flags
			args := []string{}
			if tt.flagValue != "" {
				args = append(args, "--new-region-format="+tt.flagValue)
			}
			err := fs.Parse(args)
			require.NoError(t, err)

			assert.Equal(t, tt.wantEnabled, mf.NewRegionFormat)
		})
	}
}
