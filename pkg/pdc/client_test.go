package pdc_test

import (
	"net/url"
	"testing"

	"github.com/grafana/pdc-agent/pkg/pdc"
	"github.com/stretchr/testify/assert"
)

func mustParse(s string) *url.URL {
	r, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return r
}

func TestConfig_ParseHosts(t *testing.T) {

	testcases := []struct {
		name            string
		input           pdc.Config
		expectedAPI     *url.URL
		wantGatewayErr  bool
		expectedGateway *url.URL
	}{
		{
			name:            "empty host",
			input:           *pdc.DefaultConfig(),
			expectedAPI:     mustParse(".grafana.net"),
			wantGatewayErr:  false,
			expectedGateway: mustParse(".grafana.net"),
		},
		{
			name: "contains private-datasource-connect",
			input: pdc.Config{
				Domain: "grafana.net",
				Host:   "private-datasource-connect-something",
			},
			expectedGateway: mustParse("private-datasource-connect-something.grafana.net"),
			expectedAPI:     mustParse("private-datasource-connect-api-something.grafana.net"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			api, err := tc.input.APIURL()
			assert.Nil(t, err)
			assert.Equal(t, tc.expectedAPI, api)

			gw, err := tc.input.GatewayURL()
			if tc.wantGatewayErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tc.expectedGateway, gw)
			}
		})
	}

}
