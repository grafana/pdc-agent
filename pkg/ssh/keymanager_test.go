package ssh_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/grafana/dskit/services"
	"github.com/grafana/pdc-agent/pkg/pdc"
	"github.com/grafana/pdc-agent/pkg/ssh"
	"github.com/mikesmitty/edkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

var (
	authToken    = "valid"
	knownHosts   = `known hosts`
	expectedCert = `
-----BEGIN CERTIFICATE-----
c3NoLWVkMjU1MTktY2VydC12MDFAb3BlbnNzaC5jb20gQUFBQUlITnphQzFsWkRJ
MU5URTVMV05sY25RdGRqQXhRRzl3Wlc1emMyZ3VZMjl0QUFBQUlESlIvSnNPT1Ev
UWlkdGhOVWZ3aUZoM0tDSHcySXpGaHI1dVNmOWJVR1pUQUFBQUlFMS9MRHBGd0Fl
bit6WFZNcTZuZmpBaEFtL1NpM3ZpaFJjd3ZrdG1YQUtuQUFBQUFBQUFBQUFBQUFB
Q0FBQUFBemN3TlFBQUFINEFBQUE3Y0hKcGRtRjBaUzFrWVhSaGMyOTFjbU5sTFdO
dmJtNWxZM1F1YUc5emRHVmtMV2R5WVdaaGJtRXVjM1pqTG1Oc2RYTjBaWEl1Ykc5
allXd0FBQUE3Y0hKcGRtRjBaUzFrWVhSaGMyOTFjbU5sTFdOdmJtNWxZM1F0WkdW
MkxYVnpMV05sYm5SeVlXd3RNQzVuY21GbVlXNWhMV1JsZGk1dVpYUUFBQUFBWkZP
SExBQUFBQUJrVTVVOEFBQUFBQUFBQUFBQUFBQUFBQUFDRndBQUFBZHpjMmd0Y25O
aEFBQUFBd0VBQVFBQUFnRUE5R0MzZUVjREpzYnFMQnVnMWMvQmVsUW5uNEdGYWxP
KzdJV2ZwdmU2YU9oYi8xVGRnNnVMMkRjRnRYMTlINGdycU1FV1paV0lvNHZQdHV3
UGZHQ3Rod000cWY2ZFNocUpCcC9KZDg2aENwOENTRldDZFBQNVpVWVB3RHpsNStE
ZG9zOExYVEF1czZXSWxxcGliRmJXS05NZkNTbld5M3J3UHRKeTEvbFhwT0FKenFE
VC80SWdhZFNDM0MyUFo2L1lpUzN2anJWazdFS0VKclc2Yk9oQzI3TGcybkZNVzgw
WEt5L0FsVktGa0k2OFV6Rll4QzMxbTd0VzkxOWNTOS9Gc1pFQWd4ZFdJU1VUVlg4
UW5zbHdzRUN4OUlhNmxKbU5RQ1lMU3Q1d2NaeVloOFV0T21UbDFrZjlRdGhjcXRv
Z3UybmhXRHRsWlp5cVpRS0tYaUJaRzl5YTl2WVZYdmUzbzcvUGJqNklHbFdybkFZ
ZVB4YSs4ZzdFNmY2aFMwQ3lmZExEb1BweFJFYTlzdGxFRjk2am00bC9zcUUwTCta
OVRjb0FzNTI5b0xQMkFkRStzK2xiWHR1ZlJjNHh4cWJJSW04TGlVY0pEa0NYZ0V3
MnlpK3crTFNaMUhMRGFXelVkVzVFcmgvZC9qbXV6elZyZWNaL0p3clFEem5KNFp5
VzJXUEtpTmY1bExLYkhyR2I4aFpoUEphRFVNOTlJMkVNbmNlbDNLOFlkYjl2YTFP
ZnB2TWI5SjNpcVlmTEs4dm4rSEJZNGE5eXhIWGcwNEZwV3VtR2pvaTBINkJkelFL
TkpNcUNFNVBOS0RicU1NeDc4cjRGUVJtNmlGaTdvdVRJUGRsU3FCdmt6ellIaXZQ
UFJCMGFUbWV4OHJNMFBtMXNrSnNMelpWc1Bsa0FBQUlVQUFBQURISnpZUzF6YUdF
eUxUVXhNZ0FBQWdDRkdyUTZVNHFHSVJXZE1rYlBIRCt4NDRaNFhsR08vTUhVemxP
SEtOM0gyRVIzWkxpWFJHazFmclhKU1Y5enhmb1lxOWY2TXdETU85QnZsMnJValRy
bGtwdTByaWE1cjYvSVYrZ3F2OHJXMHpNSUxkeWUyZnBqRXhlT3BReFdqU0pQeVI1
Q0NtWFFtRlkwblEwK1dNQjNiNGQ4ZHNNMGcxakc3aGhhdkk2UUdsa2MvUmpJckg1
QVZ3Z0I3dS80a2hUZE5aS3V1OE1KTkptNWprTkhUaEo2ekNLVi80SXl0dnl1MXpv
cGUxemdBTnF2K1NHd2lIS0FXUzh4N0podG9QMWhOTFpKSHRKOGVteHVjVitlRXZZ
STdQcjFZVzdkc0VUamhDQkUrZUpXd0ZBamYydUJtb1JGcEU1TzhHekg0aW91eEsw
VDJ1OTNSK09ycnNNSTlyS215bk5OcVZGcXd3VU0rUU9Sa0tIbFRoblo0K29zQ2o4
ejdzM3RnYUh4c1FkRW1mNFFEZ0ZBWnVlejlnLzJTYSsxeUhvNklURUs5Q1ZYOVJz
aTFTdElFKzVxWjF0alFjTUtqbDZ0OVU4RGhwdXFKaW5WQnBiN3NjYkVmRVlNcXR6
bTdaRzZBVmlGSm9vMjRMYkJxMi9MdEFwYUFpVU51c2ZYSUt1aTZhUlRuNlhyb0NN
WkFZRERrbkJsS0EwOC9IbHZJYko2VEZ3T2VFbzVtTjhKN3hhSUZ4Zk9PZUNQdFho
RnVYTEQrSmlyOEhuZWZyLzVVOTJjQ0dCS1VGOURYSDhQc1RYR1QxWWNQMkpGRXZL
QW1RbmNCaFJzZE4rblR0WjJ3T2NNaFpyTkpkbFdoWHlrNUNvcnYxTXhiZVBPTUFK
azl0ZGNvOFFqN0pIcFR0WnFBRm12c1E9PQo=
-----END CERTIFICATE-----
`
)

func TestKeyManager_StartingAndStopping(t *testing.T) {
	//
	cfg := &ssh.Config{}
	client, _ := pdc.NewClient(&pdc.Config{})

	// given a Key manager
	km := ssh.NewKeyManager(cfg, client, &ssh.OSFileReadWriter{})
	require.NotNil(t, km)

	ctx := context.Background()

	// When starting the km
	err := km.StartAsync(ctx)
	// Then the km should be in the starting state
	assert.NoError(t, err)
	assert.Equal(t, "Starting", km.State().String())

	// And eventually move to the running state
	err = km.AwaitRunning(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "Running", km.State().String())

	// When stopping the service
	km.StopAsync()
	assert.NoError(t, err)

	// Then is should eventually move to the terminated state
	km.AwaitTerminated(ctx)
	assert.Equal(t, "Terminated", km.State().String())
}

func TestKeyManager_EnsureKeysExist(t *testing.T) {
	// test cases:
	/*
	   - key and pubkey exist, but pub key is invalid for:
	   	- validBefore
	   	- validAfter
	   	- ??
	   - key and pubkey exist, and are valid.

	   - The above when cert exists, and doesnt/invalid

	   - signing request fails

	*/

	testcases := []struct {
		name     string
		setupFn  func(*testing.T, ssh.FileReadWriter, *ssh.Config)
		wantErr  bool
		assertFn func(*testing.T, ssh.FileReadWriter, *ssh.Config)
	}{
		{
			name:     "no key files exist: expect keys and a request to PDC for cert",
			assertFn: assertExpectedFiles,
		},
		{
			name: "only private key file exists: expect new keys and request for cert",
			setupFn: func(t *testing.T, frw ssh.FileReadWriter, cfg *ssh.Config) {
				t.Helper()
				privKey, _ := generateKeyPair()
				_ = frw.WriteFile(cfg.KeyFile, privKey, 0600)
			},
			assertFn: assertExpectedFiles,
		},
		{
			name: "both key files exist but private key is an invalid format: expect new keys and request for cert",
			setupFn: func(t *testing.T, frw ssh.FileReadWriter, cfg *ssh.Config) {
				t.Helper()
				_, pubKey := generateKeyPair()
				_ = frw.WriteFile(cfg.KeyFile+".pub", []byte(`not a private key`), 0644)
				_ = frw.WriteFile(cfg.KeyFile, pubKey, 0600)

			},
			assertFn: assertExpectedFiles,
		},
		{
			name: "both key files exist but public key is an invalid format: expect new keys and request for cert",
			setupFn: func(t *testing.T, frw ssh.FileReadWriter, cfg *ssh.Config) {
				t.Helper()
				privKey, _ := generateKeyPair()
				_ = frw.WriteFile(cfg.KeyFile, privKey, 0600)
				_ = frw.WriteFile(cfg.KeyFile+".pub", []byte(`not a public key`), 0644)
			},
			assertFn: assertExpectedFiles,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			// create default configs
			frw := newEmptyFileReadWriter()
			pdcCfg := pdc.DefaultConfig()
			pdcCfg.Host = "test"           // needed to get past legacy flags check
			pdcCfg.HostedGrafanaId = "123" // needed to get past legacy flags check
			cfg := ssh.DefaultConfig()
			cfg.PDC = pdcCfg

			// create mock PDC server and use the URL in the pdc config
			url := mockPDC(t, http.MethodPost, "/pdc/api/v1/sign-public-key", url.Values{}, 200)
			pdcCfg.API = url

			// allow test case to modify cfg and add files to frw
			if tc.setupFn != nil {
				tc.setupFn(t, frw, cfg)
			}

			client, err := pdc.NewClient(pdcCfg)
			require.Nil(t, err)

			// create svc under test
			svc := ssh.NewKeyManager(cfg, client, frw)
			err = services.StartAndAwaitRunning(ctx, svc)

			// test svc
			if tc.wantErr {
				assert.NotNil(t, err)
				return
			}
			require.Nil(t, err)

			tc.assertFn(t, frw, cfg)

			services.StopAndAwaitTerminated(ctx, svc)
		})
	}
}

// mockFileReadWriter implements ssh.FileReadWriter
type mockFileReadWriter struct {
	data map[string][]byte
}

func newEmptyFileReadWriter() *mockFileReadWriter {
	return &mockFileReadWriter{
		data: map[string][]byte{},
	}
}

func (m mockFileReadWriter) ReadFile(path string) ([]byte, error) {
	return m.data[path], nil
}

func (m *mockFileReadWriter) WriteFile(path string, data []byte, perm fs.FileMode) error {
	m.data[path] = data
	return nil
}

func mockPDC(t *testing.T, method, path string, expectedParams url.Values, code int) (u *url.URL) {
	t.Helper()

	// if expectedParams == nil {
	// 	expectedParams = url.Values{}
	// }

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, method, r.Method)
		assert.Equal(t, path, r.URL.Path)
		// q := r.URL.Query()

		// assert.EqualValues(t, expectedParams, q)
		// assert.Equal(t, "Basic "+authToken, r.Header.Get("Authorization")) // TODO need encoding

		resp := struct {
			KnownHosts  string `json:"known_hosts"`
			Certificate string `json:"certificate"`
		}{
			KnownHosts:  string(knownHosts),
			Certificate: expectedCert,
		}
		enc, err := json.Marshal(resp)
		assert.NoError(t, err)

		w.WriteHeader(code)
		_, err = w.Write(enc)
		assert.NoError(t, err)

	}))
	t.Cleanup(ts.Close)

	u, _ = url.Parse(ts.URL)
	return u
}

func mustParseCert(t *testing.T) []byte {
	t.Helper()
	block, rest := pem.Decode([]byte(expectedCert))
	log.Printf("%s", rest)
	return block.Bytes

}

func generateKeyPair() ([]byte, []byte) {

	// Generate a new private/public keypair for OpenSSH
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	sshPubKey, _ := gossh.NewPublicKey(pubKey)

	pemKey := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(privKey),
	}
	pemPrivKey := pem.EncodeToMemory(pemKey)

	// public key should be in authorized_keys file format
	return pemPrivKey, gossh.MarshalAuthorizedKey(sshPubKey)

}

func assertExpectedFiles(t *testing.T, frw ssh.FileReadWriter, cfg *ssh.Config) {
	keyFile, err := frw.ReadFile(cfg.KeyFile)
	assert.Nil(t, err)
	assert.NotNil(t, keyFile)

	pubKeyFile, err := frw.ReadFile(cfg.KeyFile + ".pub")
	assert.Nil(t, err)
	assert.NotNil(t, pubKeyFile)

	kfd := cfg.KeyFileDir()
	kh, err := frw.ReadFile(kfd + "known_hosts")
	assert.Nil(t, err)
	assert.Equal(t, string(knownHosts), string(kh))

	cert, err := frw.ReadFile(cfg.KeyFile + "-cert.pub")
	assert.Nil(t, err)
	assert.Equal(t, mustParseCert(t), cert)

}
