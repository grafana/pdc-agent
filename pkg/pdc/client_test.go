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

func TestSigningResponse_UnmarshalJSON(t *testing.T) {
	testcases := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "valid, empty fields",
			input:   []byte(`{"certificate":"","known_hosts":""}`),
			wantErr: true,
		},
		{
			name:    "invalid json",
			input:   []byte(`{invalid}`),
			wantErr: true,
		},
		{
			name:    "parsing error on certificate",
			input:   []byte(`{"known_hosts":"","certificate":"not-a-pem-file}`),
			wantErr: true,
		},
		{
			name:    "successful parse",
			input:   []byte(`{"known_hosts":"kh", "certificate":"-----BEGIN CERTIFICATE-----\nc3NoLWVkMjU1MTktY2VydC12MDFAb3BlbnNzaC5jb20gQUFBQUlITnphQzFsWkRJ\nMU5URTVMV05sY25RdGRqQXhRRzl3Wlc1emMyZ3VZMjl0QUFBQUlESlIvSnNPT1Ev\nUWlkdGhOVWZ3aUZoM0tDSHcySXpGaHI1dVNmOWJVR1pUQUFBQUlFMS9MRHBGd0Fl\nbit6WFZNcTZuZmpBaEFtL1NpM3ZpaFJjd3ZrdG1YQUtuQUFBQUFBQUFBQUFBQUFB\nQ0FBQUFBemN3TlFBQUFINEFBQUE3Y0hKcGRtRjBaUzFrWVhSaGMyOTFjbU5sTFdO\ndmJtNWxZM1F1YUc5emRHVmtMV2R5WVdaaGJtRXVjM1pqTG1Oc2RYTjBaWEl1Ykc5\nallXd0FBQUE3Y0hKcGRtRjBaUzFrWVhSaGMyOTFjbU5sTFdOdmJtNWxZM1F0WkdW\nMkxYVnpMV05sYm5SeVlXd3RNQzVuY21GbVlXNWhMV1JsZGk1dVpYUUFBQUFBWkZP\nSExBQUFBQUJrVTVVOEFBQUFBQUFBQUFBQUFBQUFBQUFDRndBQUFBZHpjMmd0Y25O\naEFBQUFBd0VBQVFBQUFnRUE5R0MzZUVjREpzYnFMQnVnMWMvQmVsUW5uNEdGYWxP\nKzdJV2ZwdmU2YU9oYi8xVGRnNnVMMkRjRnRYMTlINGdycU1FV1paV0lvNHZQdHV3\nUGZHQ3Rod000cWY2ZFNocUpCcC9KZDg2aENwOENTRldDZFBQNVpVWVB3RHpsNStE\nZG9zOExYVEF1czZXSWxxcGliRmJXS05NZkNTbld5M3J3UHRKeTEvbFhwT0FKenFE\nVC80SWdhZFNDM0MyUFo2L1lpUzN2anJWazdFS0VKclc2Yk9oQzI3TGcybkZNVzgw\nWEt5L0FsVktGa0k2OFV6Rll4QzMxbTd0VzkxOWNTOS9Gc1pFQWd4ZFdJU1VUVlg4\nUW5zbHdzRUN4OUlhNmxKbU5RQ1lMU3Q1d2NaeVloOFV0T21UbDFrZjlRdGhjcXRv\nZ3UybmhXRHRsWlp5cVpRS0tYaUJaRzl5YTl2WVZYdmUzbzcvUGJqNklHbFdybkFZ\nZVB4YSs4ZzdFNmY2aFMwQ3lmZExEb1BweFJFYTlzdGxFRjk2am00bC9zcUUwTCta\nOVRjb0FzNTI5b0xQMkFkRStzK2xiWHR1ZlJjNHh4cWJJSW04TGlVY0pEa0NYZ0V3\nMnlpK3crTFNaMUhMRGFXelVkVzVFcmgvZC9qbXV6elZyZWNaL0p3clFEem5KNFp5\nVzJXUEtpTmY1bExLYkhyR2I4aFpoUEphRFVNOTlJMkVNbmNlbDNLOFlkYjl2YTFP\nZnB2TWI5SjNpcVlmTEs4dm4rSEJZNGE5eXhIWGcwNEZwV3VtR2pvaTBINkJkelFL\nTkpNcUNFNVBOS0RicU1NeDc4cjRGUVJtNmlGaTdvdVRJUGRsU3FCdmt6ellIaXZQ\nUFJCMGFUbWV4OHJNMFBtMXNrSnNMelpWc1Bsa0FBQUlVQUFBQURISnpZUzF6YUdF\neUxUVXhNZ0FBQWdDRkdyUTZVNHFHSVJXZE1rYlBIRCt4NDRaNFhsR08vTUhVemxP\nSEtOM0gyRVIzWkxpWFJHazFmclhKU1Y5enhmb1lxOWY2TXdETU85QnZsMnJValRy\nbGtwdTByaWE1cjYvSVYrZ3F2OHJXMHpNSUxkeWUyZnBqRXhlT3BReFdqU0pQeVI1\nQ0NtWFFtRlkwblEwK1dNQjNiNGQ4ZHNNMGcxakc3aGhhdkk2UUdsa2MvUmpJckg1\nQVZ3Z0I3dS80a2hUZE5aS3V1OE1KTkptNWprTkhUaEo2ekNLVi80SXl0dnl1MXpv\ncGUxemdBTnF2K1NHd2lIS0FXUzh4N0podG9QMWhOTFpKSHRKOGVteHVjVitlRXZZ\nSTdQcjFZVzdkc0VUamhDQkUrZUpXd0ZBamYydUJtb1JGcEU1TzhHekg0aW91eEsw\nVDJ1OTNSK09ycnNNSTlyS215bk5OcVZGcXd3VU0rUU9Sa0tIbFRoblo0K29zQ2o4\nejdzM3RnYUh4c1FkRW1mNFFEZ0ZBWnVlejlnLzJTYSsxeUhvNklURUs5Q1ZYOVJz\naTFTdElFKzVxWjF0alFjTUtqbDZ0OVU4RGhwdXFKaW5WQnBiN3NjYkVmRVlNcXR6\nbTdaRzZBVmlGSm9vMjRMYkJxMi9MdEFwYUFpVU51c2ZYSUt1aTZhUlRuNlhyb0NN\nWkFZRERrbkJsS0EwOC9IbHZJYko2VEZ3T2VFbzVtTjhKN3hhSUZ4Zk9PZUNQdFho\nRnVYTEQrSmlyOEhuZWZyLzVVOTJjQ0dCS1VGOURYSDhQc1RYR1QxWWNQMkpGRXZL\nQW1RbmNCaFJzZE4rblR0WjJ3T2NNaFpyTkpkbFdoWHlrNUNvcnYxTXhiZVBPTUFK\nazl0ZGNvOFFqN0pIcFR0WnFBRm12c1E9PQo=\n-----END CERTIFICATE-----\n"}`),
			wantErr: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result := &pdc.SigningResponse{}
			err := result.UnmarshalJSON(tc.input)

			if tc.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.NotNil(t, result.KnownHosts)
				assert.NotNil(t, result.Certificate)
			}
		})
	}
}
