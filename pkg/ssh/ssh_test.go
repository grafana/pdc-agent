package ssh_test

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/go-kit/log"
	"github.com/grafana/pdc-agent/pkg/pdc"
	"github.com/grafana/pdc-agent/pkg/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

var certPEM = `
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

func mustParseURL(s string) *url.URL {
	url, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return url
}

func TestStartingAndStopping(t *testing.T) {
	// Given an SSH client
	client := newTestClient(t, &ssh.Config{}, true)

	ctx := context.Background()

	// When starting the client
	err := client.StartAsync(ctx)
	// Then the client should be in the starting state
	assert.NoError(t, err)
	assert.Equal(t, "Starting", client.State().String())

	// And eventually move to the running state
	err = client.AwaitRunning(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "Running", client.State().String())

	// When stopping the service
	client.StopAsync()
	assert.NoError(t, err)

	// Then is should eventually move to the terminated state
	_ = client.AwaitTerminated(ctx)
	assert.Equal(t, "Terminated", client.State().String())

}

// testClient returns a new SSH client with a mocked command
// see https://npf.io/2015/06/testing-exec-command/
func newTestClient(t *testing.T, cfg *ssh.Config, mockCmd bool) *ssh.Client {
	t.Helper()
	logger := log.NewNopLogger()
	if mockCmd {
		cfg.Args = append([]string{"-test.run=TestFakeSSHCmd", "--"}, cfg.Args...)
		cfg.LegacyMode = true
	}

	if cfg.URL == nil {
		cfg.URL = mustParseURL("localhost")
	}

	cfg.SkipSSHValidation = true

	dir := t.TempDir()
	cfg.KeyFile = path.Join(dir, "test_cert")

	mClient := mockPDCClient{}
	km := ssh.NewKeyManager(cfg, logger, mClient)

	client := ssh.NewClient(cfg, logger, km)
	client.SSHCmd = os.Args[0]
	return client
}

// TestFakeSSHCmd is a test helper function that is executed by the SSH client
func TestFakeSSHCmd(t *testing.T) {
	assert.True(t, true)
}

// Building this out to verify behaviour, not exactly sure that the function is
// hanging off the right struct or organised appropriately.
func TestClient_SSHArgs(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg := ssh.DefaultConfig()

		cfg.URL = mustParseURL("host.grafana.net")

		cfg.PDC = pdc.Config{
			HostedGrafanaID: "123",
		}

		sshClient := newTestClient(t, cfg, false)

		result, err := sshClient.SSHFlagsFromConfig()

		assert.Nil(t, err)
		assert.Equal(t, strings.Split(fmt.Sprintf("-i %s 123@host.grafana.net -p 22 -R 0 -o CertificateFile=%s -o ConnectTimeout=1 -o ServerAliveInterval=15 -o TCPKeepAlive=no -o UserKnownHostsFile=%s -vvv", cfg.KeyFile, cfg.KeyFile+certSuffix, path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile)), " "), result)
	})

	t.Run("legacy args (deprecated)", func(t *testing.T) {
		expectedArgs := []string{"test", "ok"}
		cfg := ssh.DefaultConfig()
		cfg.LegacyMode = true
		cfg.URL = mustParseURL("localhost")
		cfg.Args = expectedArgs

		sshClient := newTestClient(t, cfg, false)
		result, err := sshClient.SSHFlagsFromConfig()

		assert.Nil(t, err)
		assert.Equal(t, expectedArgs, result)
	})

	t.Run("ssh-flags get appended to command", func(t *testing.T) {
		cfg := ssh.DefaultConfig()

		cfg.URL = mustParseURL("host.grafana.net")

		cfg.PDC = pdc.Config{
			HostedGrafanaID: "123",
		}

		cfg.SSHFlags = []string{
			"-o TestOption=2",
			"-o PermitRemoteOpen=host:123 host:456",
			"-o ConnectTimeout=3",
		}

		sshClient := newTestClient(t, cfg, false)
		result, err := sshClient.SSHFlagsFromConfig()

		assert.Nil(t, err)
		expected := []string{
			"-i",
			cfg.KeyFile,
			"123@host.grafana.net",
			"-p",
			"22",
			"-R",
			"0",
			"-o", fmt.Sprintf("CertificateFile=%s", cfg.KeyFile+certSuffix),
			"-o", "ConnectTimeout=3",
			"-o", "PermitRemoteOpen=host:123 host:456",
			"-o", "ServerAliveInterval=15",
			"-o", "TCPKeepAlive=no",
			"-o", "TestOption=2",
			"-o", fmt.Sprintf("UserKnownHostsFile=%s", path.Join(cfg.KeyFileDir(), ssh.KnownHostsFile)),
			"-vvv",
		}
		assert.Equal(t, expected, result)

	})

	t.Run("errors on invalid option flag", func(t *testing.T) {
		cfg := ssh.DefaultConfig()

		cfg.URL = mustParseURL("host.grafana.net")
		cfg.PDC = pdc.Config{
			HostedGrafanaID: "123",
		}

		cfg.SSHFlags = []string{
			"-o TestOption invalid format",
		}

		sshClient := newTestClient(t, cfg, false)
		_, err := sshClient.SSHFlagsFromConfig()
		assert.NotNil(t, err)
		assert.Equal(t, err.Error(), "invalid ssh option format, expecting '-o Name=string'")
	})
}

func TestSSHVersionValidation(t *testing.T) {
	testcases := []struct {
		version string
		valid   bool
	}{
		{
			version: "TestSSH_9.2",
			valid:   false,
		},
		{
			version: "OpenSSH_test",
			valid:   false,
		},
		{
			version: "OpenSSH_8.9",
			valid:   false,
		},
		{
			version: "OpenSSH_9.1 test ssh metadata",
			valid:   false,
		},
		{
			version: "OpenSSH_9.2, test ssh metadata",
			valid:   true,
		},
		{
			version: "OpenSSH_9.200p1, test ssh metadata",
			valid:   true,
		},
		{
			version: "OpenSSH_9.2p1",
			valid:   true,
		},
		{
			version: "OpenSSH_19.1p1, test ssh metadata",
			valid:   true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.version, func(t *testing.T) {
			major, minor, err := ssh.ParseSSHVersion(tc.version)

			if tc.valid {
				require.NoError(t, err)
				err := ssh.RequireSSHVersionAbove9_2(major, minor)
				require.NoError(t, err)
			} else {
				err := ssh.RequireSSHVersionAbove9_2(major, minor)
				require.Error(t, err)
			}
		})
	}

}

type mockPDCClient struct {
}

func (m mockPDCClient) SignSSHKey(_ context.Context, _ []byte) (*pdc.SigningResponse, error) {

	block, _ := pem.Decode([]byte(certPEM))
	pk, _, _, _, err := gossh.ParseAuthorizedKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	cert, _ := pk.(*gossh.Certificate)

	return &pdc.SigningResponse{
		KnownHosts:  []byte("known hosts"),
		Certificate: *cert,
	}, nil
}
