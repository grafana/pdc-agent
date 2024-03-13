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
	"sync"
	"testing"
	"time"

	"github.com/go-kit/log"

	"github.com/grafana/pdc-agent/pkg/pdc"
	"github.com/grafana/pdc-agent/pkg/ssh"
	"github.com/mikesmitty/edkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
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

// Contains a KeyManager that can be used for testing
// and the values used to create it.
type testKeyManagerOutput struct {
	pdcCfg pdc.Config
	sshCfg *ssh.Config
	km     *ssh.KeyManager
	pdc    *mockPDC
}

// Instantiates and returns a KeyManager that can be used for testing.
func testKeyManager(t *testing.T) testKeyManagerOutput {
	t.Helper()

	// create default configs
	pdcCfg := pdc.Config{HostedGrafanaID: "1"}
	sshCfg := ssh.DefaultConfig()
	sshCfg.PDC = pdcCfg
	sshCfg.CertCheckCertExpiryPeriod = 1 * time.Second
	sshCfg.CertExpiryWindow = 1 * time.Minute

	sshCfg.KeyFile = path.Join(t.TempDir(), "testkey")

	m := newMockPDC(t, http.MethodPost, "/pdc/api/v1/sign-public-key", http.StatusOK)
	pdcCfg.URL = m.URL()

	logger := log.NewNopLogger()

	client, err := pdc.NewClient(&pdcCfg, logger)
	require.Nil(t, err)

	return testKeyManagerOutput{
		pdcCfg: pdcCfg,
		sshCfg: sshCfg,
		km:     ssh.NewKeyManager(sshCfg, logger, client),
		pdc:    m,
	}
}

func TestKeyManager_CreateKeys(t *testing.T) {
	t.Parallel()

	t.Run("ssh key pairs are reused by default, a new ssh pair is not created each time", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		sut := testKeyManager(t)

		// The first call to CreateKeys will create a new ssh pair.
		assert.NoError(t, sut.km.CreateKeys(ctx, false))

		// Read the private key that was just created.
		key1, err := os.ReadFile(sut.sshCfg.KeyFile)
		assert.NotEmpty(t, key1)
		assert.NoError(t, err)

		// The second call to CreateKeys will see that a ssh pair already exists
		// and it'll not create a new one.
		assert.NoError(t, sut.km.CreateKeys(ctx, false))

		// Read the key again, it should be the same key we read before.
		key2, err := os.ReadFile(sut.sshCfg.KeyFile)
		assert.NoError(t, err)
		assert.NotEmpty(t, key2)

		assert.Equal(t, key1, key2)
	})

	t.Run("a flag can be used to force a new ssh pair to be generated, should generate a new ssh key pair even if a key pair already exists", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		sut := testKeyManager(t)

		// Force the creation of a new ssh key pair.
		sut.sshCfg.ForceKeyFileOverwrite = true

		// The first call to CreateKeys will create a new ssh pair.
		assert.NoError(t, sut.km.CreateKeys(ctx, sut.sshCfg.ForceKeyFileOverwrite))

		// Read the private key that was just created.
		key1, err := os.ReadFile(sut.sshCfg.KeyFile)
		assert.NotEmpty(t, key1)
		assert.NoError(t, err)

		// The second call to CreateKeys will create a new ssh key pair even though a key pair already exists.
		assert.NoError(t, sut.km.CreateKeys(ctx, sut.sshCfg.ForceKeyFileOverwrite))

		// Read the private key that was just created.
		key2, err := os.ReadFile(sut.sshCfg.KeyFile)
		assert.NotEmpty(t, key2)
		assert.NoError(t, err)

		// A new key should have been generated.
		assert.NotEqual(t, key1, key2)
	})
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
				_ = os.WriteFile(cfg.KeyFile+pubSuffix, pubKey, 0644)
				_ = os.WriteFile(cfg.KeyFile+certSuffix, cert, 0644)
				_ = os.WriteFile(path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), kh, 0644)
				_ = os.WriteFile(cfg.KeyFile+hashSuffix, []byte("6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"), 0644)
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
				_ = os.WriteFile(cfg.KeyFile+pubSuffix, []byte("not a public key"), 0644)
				_ = os.WriteFile(cfg.KeyFile+certSuffix, cert, 0644)
				_ = os.WriteFile(path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), kh, 0644)
				_ = os.WriteFile(cfg.KeyFile+hashSuffix, []byte("6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"), 0644)
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
				_ = os.WriteFile(cfg.KeyFile+pubSuffix, pubKey, 0644)
				_ = os.WriteFile(cfg.KeyFile+certSuffix, []byte("invalid cert"), 0644)
				_ = os.WriteFile(path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), kh, 0644)
				_ = os.WriteFile(cfg.KeyFile+hashSuffix, []byte("6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"), 0644)
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
				_ = os.WriteFile(cfg.KeyFile+pubSuffix, pubKey, 0644)
				_ = os.WriteFile(cfg.KeyFile+certSuffix, cert, 0644)
				_ = os.WriteFile(path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), []byte("invalid known_hosts"), 0644)
				_ = os.WriteFile(cfg.KeyFile+hashSuffix, []byte("6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"), 0644)
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
			name: "valid keys, cert, known_hosts and agent arguments have not changed: no signing request",
			setupFn: func(t *testing.T, cfg *ssh.Config) {
				t.Helper()
				privKey, pubKey, cert, kh := generateKeys("", "")
				_ = os.WriteFile(cfg.KeyFile, privKey, 0600)
				_ = os.WriteFile(cfg.KeyFile+pubSuffix, pubKey, 0644)
				_ = os.WriteFile(cfg.KeyFile+certSuffix, cert, 0644)
				_ = os.WriteFile(path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), kh, 0644)
				_ = os.WriteFile(cfg.KeyFile+hashSuffix, []byte("6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"), 0644)
			},
			wantSigningRequest: false,
			assertFn: func(t *testing.T, cfg *ssh.Config) {
				keyFile, err := os.ReadFile(cfg.KeyFile)
				assert.NoError(t, err)
				assert.NotNil(t, keyFile)

				pubKeyFile, err := os.ReadFile(cfg.KeyFile + pubSuffix)
				assert.NoError(t, err)
				assert.NotNil(t, pubKeyFile)

				kfd := cfg.KeyFileDir()
				_, err = os.ReadFile(path.Join(kfd, ssh.KnownHostsFile))
				assert.NoError(t, err)

				cert, err := os.ReadFile(cfg.KeyFile + certSuffix)
				assert.NoError(t, err)
				_, _, _, _, err = gossh.ParseAuthorizedKey(cert)
				assert.NoError(t, err)

				contents, err := os.ReadFile(cfg.KeyFile + hashSuffix)
				assert.NoError(t, err)
				assert.NotEmpty(t, contents)
			},
		},
		{
			name: "cert outside validity window: expect signing request",
			setupFn: func(t *testing.T, cfg *ssh.Config) {
				t.Helper()
				// gen cert with validity period in the past
				privKey, pubKey, cert, kh := generateKeys("-10m", "-1h")
				_ = os.WriteFile(cfg.KeyFile, privKey, 0600)
				_ = os.WriteFile(cfg.KeyFile+pubSuffix, pubKey, 0644)
				_ = os.WriteFile(cfg.KeyFile+certSuffix, cert, 0644)
				_ = os.WriteFile(path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), kh, 0644)
			},
			wantSigningRequest: true,
			assertFn:           assertExpectedFiles,
		},
		{
			name: "agent arguments have changed, should generate new cert: expect signing request",
			setupFn: func(t *testing.T, cfg *ssh.Config) {
				t.Helper()
				// gen cert with validity period in the past
				privKey, pubKey, cert, kh := generateKeys("", "")
				_ = os.WriteFile(cfg.KeyFile, privKey, 0600)
				_ = os.WriteFile(cfg.KeyFile+pubSuffix, pubKey, 0644)
				_ = os.WriteFile(cfg.KeyFile+certSuffix, cert, 0644)
				_ = os.WriteFile(path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), kh, 0644)
				// The new argument hash is different from the previous one.
				_ = os.WriteFile(cfg.KeyFile+hashSuffix, []byte("some hash"), 0644)
			},
			wantSigningRequest: true,
			assertFn:           assertExpectedFiles,
		},
		{
			name: "cert is valid but an argument hash file does not exist, should generate new cert because arguments may have changed: expect signing request",
			setupFn: func(t *testing.T, cfg *ssh.Config) {
				t.Helper()
				// gen cert with validity period in the past
				privKey, pubKey, cert, kh := generateKeys("", "")
				_ = os.WriteFile(cfg.KeyFile, privKey, 0600)
				_ = os.WriteFile(cfg.KeyFile+pubSuffix, pubKey, 0644)
				_ = os.WriteFile(cfg.KeyFile+certSuffix, cert, 0644)
				_ = os.WriteFile(path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile), kh, 0644)
				// Note that we are not creating a hash file.
			},
			wantSigningRequest: true,
			assertFn:           assertExpectedFiles,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			// create default configs
			pdcCfg := pdc.Config{HostedGrafanaID: "1"}
			cfg := ssh.DefaultConfig()
			cfg.PDC = pdcCfg

			cfg.KeyFile = path.Join(t.TempDir(), "testkey")

			// create mock PDC server and use the URL in the pdc config
			if tc.apiResponseCode == 0 {
				tc.apiResponseCode = 200
			}
			m := newMockPDC(t, http.MethodPost, "/pdc/api/v1/sign-public-key", tc.apiResponseCode)
			pdcCfg.URL = m.URL()

			// allow test case to modify cfg and add files to frw
			if tc.setupFn != nil {
				tc.setupFn(t, cfg)
			}

			logger := log.NewNopLogger()

			client, err := pdc.NewClient(&pdcCfg, logger)
			require.Nil(t, err)

			km := ssh.NewKeyManager(cfg, logger, client)
			err = km.CreateKeys(ctx, false)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.Nil(t, err)

			if tc.wantSigningRequest {
				assert.True(t, m.CalledCount() > 0)
			}

			if tc.assertFn != nil {
				tc.assertFn(t, cfg)
			}
		})
	}
}

func TestBackgroundRefresh(t *testing.T) {
	t.Run("refresh is 0, do not refresh", func(t *testing.T) {
		ctx := context.Background()
		sut := testKeyManager(t)
		sut.sshCfg.CertCheckCertExpiryPeriod = 0

		require.Nil(t, sut.km.Start(ctx))
		<-time.After(2 * time.Second)

		// key signing is only called once (at start)
		assert.Equal(t, 1, sut.pdc.CalledCount())
	})

	t.Run("new cert requested whenever cert is within expiry window", func(t *testing.T) {
		ctx := context.Background()
		// given a keymanager with a cert that is always expired
		sut := testKeyManager(t)
		sut.sshCfg.CertCheckCertExpiryPeriod = 100 * time.Millisecond
		require.Nil(t, sut.km.Start(ctx))

		// leave enough time for the ticker to tick 9 times
		<-time.After(910 * time.Millisecond)

		// key signing is called a total of 10 times (once at start)
		assert.Equal(t, 10, sut.pdc.CalledCount())

	})
}

type mockPDC struct {
	method string
	path   string
	code   int
	ts     *httptest.Server
	t      *testing.T

	mu          sync.Mutex
	calledCount int
}

func (m *mockPDC) Reset() {
	m.calledCount = 0
}

func (m *mockPDC) URL() *url.URL {
	url, _ := url.Parse(m.ts.URL)
	return url
}

func (m *mockPDC) CalledCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calledCount
}

func (m *mockPDC) handlerFunc(w http.ResponseWriter, r *http.Request) {
	assert.Equal(m.t, m.method, r.Method)
	assert.Equal(m.t, m.path, r.URL.Path)

	m.mu.Lock()
	m.calledCount++
	m.mu.Unlock()

	resp := struct {
		KnownHosts  string `json:"known_hosts"`
		Certificate string `json:"certificate"`
	}{
		KnownHosts:  knownHosts,
		Certificate: expectedCert,
	}
	enc, err := json.Marshal(resp)
	assert.NoError(m.t, err)

	w.WriteHeader(m.code)
	_, err = w.Write(enc)
	assert.NoError(m.t, err)

}

func newMockPDC(t *testing.T, method, path string, code int) *mockPDC {
	t.Helper()

	m := &mockPDC{
		calledCount: 0,
		method:      method,
		code:        code,
		path:        path,
		t:           t,
	}

	ts := httptest.NewServer(http.HandlerFunc(m.handlerFunc))
	m.ts = ts
	t.Cleanup(ts.Close)
	return m
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

	pubKeyFile, err := os.ReadFile(cfg.KeyFile + pubSuffix)
	assert.NoError(t, err)
	assert.NotNil(t, pubKeyFile)

	kfd := cfg.KeyFileDir()
	kh, err := os.ReadFile(kfd + ssh.KnownHostsFile)
	assert.NoError(t, err)
	assert.Equal(t, knownHosts, string(kh))

	cert, err := os.ReadFile(cfg.KeyFile + certSuffix)
	assert.NoError(t, err)
	assert.Equal(t, mustParseCert(t), cert)

	contents, err := os.ReadFile(cfg.KeyFile + hashSuffix)
	assert.NoError(t, err)
	assert.NotEmpty(t, contents)
}
