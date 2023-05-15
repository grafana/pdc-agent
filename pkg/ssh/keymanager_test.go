package ssh_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"testing"
	"time"

	"github.com/go-kit/log"

	"github.com/grafana/dskit/services"
	"github.com/grafana/pdc-agent/pkg/pdc"
	"github.com/grafana/pdc-agent/pkg/ssh"
	"github.com/mikesmitty/edkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
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
	logger := log.NewNopLogger()
	cfg := ssh.DefaultConfig()
	cfg.URL = mustParseURL("ssh.local")

	cfg.KeyFile = path.Join(t.TempDir(), "testkey")

	// given a Key manager
	km := ssh.NewKeyManager(cfg, logger, mockClient{})
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
	err = km.AwaitTerminated(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "Terminated", km.State().String())
}

func TestKeyManager_EnsureKeysExist(t *testing.T) {
	testcases := []struct {
		name               string
		setupFn            func(*testing.T, *ssh.Config)
		wantErr            bool
		assertFn           func(*testing.T, *ssh.Config)
		apiResponseCode    int
		wantSigningRequest bool
	}{
		{
			name:               "no key files exist: expect keys and a request to PDC for cert",
			assertFn:           assertExpectedFiles,
			wantSigningRequest: true,
		},
		{
			name: "only private key file exists: expect new keys and request for cert",
			setupFn: func(t *testing.T, cfg *ssh.Config) {
				t.Helper()
				privKey, _, _, _ := generateKeys("", "")
				_ = os.WriteFile(cfg.KeyFile, privKey, 0600)
			},
			assertFn:           assertExpectedFiles,
			wantSigningRequest: true,
		},
		{
			name: "all key files exist but private key is an invalid format: expect new keys and request for cert",
			setupFn: func(t *testing.T, cfg *ssh.Config) {
				t.Helper()
				_, pubKey, cert, kh := generateKeys("", "")
				_ = os.WriteFile(cfg.KeyFile, []byte("invalid private key"), 0600)
				_ = os.WriteFile(cfg.KeyFile+".pub", pubKey, 0644)
				_ = os.WriteFile(cfg.KeyFile+"-cert.pub", cert, 0644)
				_ = os.WriteFile(path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), kh, 0644)

			},
			assertFn:           assertExpectedFiles,
			wantSigningRequest: true,
		},
		{
			name: "all key files exist but public key is an invalid format: expect new keys and request for cert",
			setupFn: func(t *testing.T, cfg *ssh.Config) {
				t.Helper()
				privKey, _, cert, kh := generateKeys("", "")
				_ = os.WriteFile(cfg.KeyFile, privKey, 0600)
				_ = os.WriteFile(cfg.KeyFile+".pub", []byte("not a public key"), 0644)
				_ = os.WriteFile(cfg.KeyFile+"-cert.pub", cert, 0644)
				_ = os.WriteFile(path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), kh, 0644)
			},
			assertFn:           assertExpectedFiles,
			wantSigningRequest: true,
		},
		{
			name: "all key files exist but cert is invalid: expect new keys and request for cert",
			setupFn: func(t *testing.T, cfg *ssh.Config) {
				t.Helper()
				privKey, pubKey, _, kh := generateKeys("", "")
				_ = os.WriteFile(cfg.KeyFile, privKey, 0600)
				_ = os.WriteFile(cfg.KeyFile+".pub", pubKey, 0644)
				_ = os.WriteFile(cfg.KeyFile+"-cert.pub", []byte("invalid cert"), 0644)
				_ = os.WriteFile(path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), kh, 0644)
			},
			assertFn:           assertExpectedFiles,
			wantSigningRequest: true,
		},
		{
			name: "valid keys and cert, but invalid known_hosts: call signing request",
			setupFn: func(t *testing.T, cfg *ssh.Config) {
				t.Helper()
				privKey, pubKey, cert, _ := generateKeys("", "")
				_ = os.WriteFile(cfg.KeyFile, privKey, 0600)
				_ = os.WriteFile(cfg.KeyFile+".pub", pubKey, 0644)
				_ = os.WriteFile(cfg.KeyFile+"-cert.pub", cert, 0644)
				_ = os.WriteFile(path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), []byte("invalid known_hosts"), 0644)

			},
			wantSigningRequest: true,
			assertFn:           assertExpectedFiles,
		},
		{
			name:            "Signing request fails, expect error",
			apiResponseCode: 400,
			wantErr:         true,
		},
		{
			name: "valid keys, cert and known_hosts: no signing request",
			setupFn: func(t *testing.T, cfg *ssh.Config) {
				t.Helper()
				privKey, pubKey, cert, kh := generateKeys("", "")
				_ = os.WriteFile(cfg.KeyFile, privKey, 0600)
				_ = os.WriteFile(cfg.KeyFile+".pub", pubKey, 0644)
				_ = os.WriteFile(cfg.KeyFile+"-cert.pub", cert, 0644)
				_ = os.WriteFile(path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), kh, 0644)
			},
			wantSigningRequest: false,
			assertFn: func(t *testing.T, cfg *ssh.Config) {
				keyFile, err := os.ReadFile(cfg.KeyFile)
				assert.NoError(t, err)
				assert.NotNil(t, keyFile)

				pubKeyFile, err := os.ReadFile(cfg.KeyFile + ".pub")
				assert.NoError(t, err)
				assert.NotNil(t, pubKeyFile)

				kfd := cfg.KeyFileDir()
				_, err = os.ReadFile(path.Join(kfd, ssh.KnownHostsFile))
				assert.NoError(t, err)

				cert, err := os.ReadFile(cfg.KeyFile + "-cert.pub")
				assert.NoError(t, err)
				_, _, _, _, err = gossh.ParseAuthorizedKey(cert)
				assert.NoError(t, err)
			},
		},
		{
			name: "cert outside validity window: expect signing request",
			setupFn: func(t *testing.T, cfg *ssh.Config) {
				t.Helper()
				// gen cert with validity period in the past
				privKey, pubKey, cert, kh := generateKeys("-10m", "-1h")
				_ = os.WriteFile(cfg.KeyFile, privKey, 0600)
				_ = os.WriteFile(cfg.KeyFile+".pub", pubKey, 0644)
				_ = os.WriteFile(cfg.KeyFile+"-cert.pub", cert, 0644)
				_ = os.WriteFile(path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), kh, 0644)
			},
			wantSigningRequest: true,
			assertFn:           assertExpectedFiles,
		},
		{
			name: "forceKeyFileOverwrite is true: expect signing request",
			setupFn: func(t *testing.T, cfg *ssh.Config) {
				t.Helper()
				privKey, pubKey, cert, kh := generateKeys("", "")
				_ = os.WriteFile(cfg.KeyFile, privKey, 0600)
				_ = os.WriteFile(cfg.KeyFile+".pub", pubKey, 0644)
				_ = os.WriteFile(cfg.KeyFile+"-cert.pub", cert, 0644)
				_ = os.WriteFile(path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), kh, 0644)
				cfg.ForceKeyFileOverwrite = true
			},
			wantSigningRequest: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			// create default configs
			pdcCfg := pdc.Config{}
			cfg := ssh.DefaultConfig()
			cfg.PDC = pdcCfg

			cfg.KeyFile = path.Join(t.TempDir(), "testkey")

			// create mock PDC server and use the URL in the pdc config
			if tc.apiResponseCode == 0 {
				tc.apiResponseCode = 200
			}
			url, called := mockPDC(t, http.MethodPost, "/pdc/api/v1/sign-public-key", tc.apiResponseCode)
			pdcCfg.URL = url

			// allow test case to modify cfg and add files to frw
			if tc.setupFn != nil {
				tc.setupFn(t, cfg)
			}

			logger := log.NewNopLogger()

			client, err := pdc.NewClient(&pdcCfg, logger)
			require.Nil(t, err)

			// create svc under test
			svc := ssh.NewKeyManager(cfg, logger, client)
			err = services.StartAndAwaitRunning(ctx, svc)

			// test svc
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.Nil(t, err)

			assert.Equal(t, tc.wantSigningRequest, *called)

			if tc.assertFn != nil {
				tc.assertFn(t, cfg)
			}

			_ = services.StopAndAwaitTerminated(ctx, svc)
		})
	}
}

type mockClient struct {
}

func (mc mockClient) SignSSHKey(_ context.Context, _ []byte) (*pdc.SigningResponse, error) {

	_, _, cert, knownhosts := generateKeys("", "")

	pbk, _, _, _, _ := gossh.ParseAuthorizedKey(cert)
	c, _ := pbk.(*gossh.Certificate)
	return &pdc.SigningResponse{
		Certificate: *c,
		KnownHosts:  knownhosts,
	}, nil
}

func mockPDC(t *testing.T, method, path string, code int) (u *url.URL, called *bool) {
	t.Helper()

	called = new(bool)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, method, r.Method)
		assert.Equal(t, path, r.URL.Path)
		*called = true

		resp := struct {
			KnownHosts  string `json:"known_hosts"`
			Certificate string `json:"certificate"`
		}{
			KnownHosts:  knownHosts,
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
	return u, called
}

func mustParseCert(t *testing.T) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(expectedCert))
	return block.Bytes

}

func generateKeys(validBeforeDur string, validAfterDur string) ([]byte, []byte, []byte, []byte) {
	caKey, _ := rsa.GenerateKey(rand.Reader, ssh.SSHKeySize)

	// Generate a new private/public keypair for OpenSSH
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	sshPubKey, _ := gossh.NewPublicKey(pubKey)

	pemKey := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(privKey),
	}
	pemPrivKey := pem.EncodeToMemory(pemKey)

	caSigner, _ := gossh.NewSignerFromKey(caKey)

	if validBeforeDur == "" {
		validBeforeDur = "1h"
	}

	if validAfterDur == "" {
		validAfterDur = "-5m"
	}

	d, _ := time.ParseDuration(validBeforeDur)
	subd, _ := time.ParseDuration(validAfterDur)
	cert := &gossh.Certificate{
		Key:             sshPubKey,
		CertType:        gossh.UserCert,
		KeyId:           "key",
		ValidPrincipals: []string{"key"},
		ValidBefore:     uint64(time.Now().Add(d).Unix()),
		ValidAfter:      uint64(time.Now().Add(subd).Unix()),
	}

	_ = cert.SignCert(rand.Reader, caSigner)

	kh := knownhosts.Line([]string{"test.local.address"}, sshPubKey)

	fmt.Println(kh)

	// public key should be in authorized_keys file format
	return pemPrivKey, gossh.MarshalAuthorizedKey(sshPubKey), gossh.MarshalAuthorizedKey(cert), []byte(kh)

}

func assertExpectedFiles(t *testing.T, cfg *ssh.Config) {
	keyFile, err := os.ReadFile(cfg.KeyFile)
	assert.NoError(t, err)
	assert.NotNil(t, keyFile)

	pubKeyFile, err := os.ReadFile(cfg.KeyFile + ".pub")
	assert.NoError(t, err)
	assert.NotNil(t, pubKeyFile)

	kfd := cfg.KeyFileDir()
	kh, err := os.ReadFile(kfd + ssh.KnownHostsFile)
	assert.NoError(t, err)
	assert.Equal(t, knownHosts, string(kh))

	cert, err := os.ReadFile(cfg.KeyFile + "-cert.pub")
	assert.NoError(t, err)
	assert.Equal(t, mustParseCert(t), cert)

}
