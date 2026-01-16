package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateURLs(t *testing.T) {
	tests := []struct {
		name         string
		cluster      string
		domain       string
		regionFormat bool
		apiFQDN      string
		gatewayFQDN  string
		wantAPI      string
		wantGW       string
	}{
		// Old format tests (default behavior)
		{
			name:         "old format - default domain",
			cluster:      "some-cluster",
			domain:       "grafana.net",
			regionFormat: false,
			wantAPI:      "https://private-datasource-connect-api-some-cluster.grafana.net",
			wantGW:       "private-datasource-connect-some-cluster.grafana.net",
		},
		{
			name:         "old format - custom domain",
			cluster:      "some-cluster",
			domain:       "some-domain.net",
			regionFormat: false,
			wantAPI:      "https://private-datasource-connect-api-some-cluster.some-domain.net",
			wantGW:       "private-datasource-connect-some-cluster.some-domain.net",
		},
		// New format tests
		{
			name:         "new format - default domain",
			cluster:      "some-cluster",
			domain:       "grafana.net",
			regionFormat: true,
			wantAPI:      "https://private-datasource-connect-api.some-cluster.grafana.net",
			wantGW:       "private-datasource-connect.some-cluster.grafana.net",
		},
		{
			name:         "new format - custom domain",
			cluster:      "some-cluster",
			domain:       "some-domain.net",
			regionFormat: true,
			wantAPI:      "https://private-datasource-connect-api.some-cluster.some-domain.net",
			wantGW:       "private-datasource-connect.some-cluster.some-domain.net",
		},
		// Custom FQDN precedence tests
		{
			name:         "custom api-fqdn overrides format",
			cluster:      "some-cluster",
			domain:       "some-domain.net",
			regionFormat: true,
			apiFQDN:      "custom-api.example.com",
			wantAPI:      "https://custom-api.example.com",
			wantGW:       "private-datasource-connect.some-cluster.some-domain.net",
		},
		{
			name:         "custom gateway-fqdn overrides format",
			cluster:      "some-cluster",
			domain:       "some-domain.net",
			regionFormat: true,
			gatewayFQDN:  "custom-gateway.example.com",
			wantAPI:      "https://private-datasource-connect-api.some-cluster.some-domain.net",
			wantGW:       "custom-gateway.example.com",
		},
		{
			name:         "both custom FQDNs override format",
			cluster:      "some-cluster",
			domain:       "some-domain.net",
			regionFormat: true,
			apiFQDN:      "custom-api.example.com",
			gatewayFQDN:  "custom-gateway.example.com",
			wantAPI:      "https://custom-api.example.com",
			wantGW:       "custom-gateway.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &mainFlags{
				Cluster:      tt.cluster,
				Domain:       tt.domain,
				RegionFormat: tt.regionFormat,
				APIFQDN:      tt.apiFQDN,
				GatewayFQDN:  tt.gatewayFQDN,
			}

			apiURL, gatewayURL, err := createURLs(cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAPI, apiURL.String())
			assert.Equal(t, tt.wantGW, gatewayURL.String())
		})
	}
}
