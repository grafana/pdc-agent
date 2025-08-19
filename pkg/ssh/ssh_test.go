package ssh_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

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

type testServer struct {
	connectionsCount int
	mu               sync.Mutex
	listener         net.Listener
}

func (s *testServer) Start() error {
	// Create a host key pair
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		return err
	}

	config := &gossh.ServerConfig{
		NoClientAuth: true,
	}
	config.AddHostKey(signer)

	// Start the SSH server listener
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", ":2200")
	if err != nil {
		return err
	}
	s.listener = listener
	go func() {
		for {
			tcpConn, err := listener.Accept()
			// DONT "require" in here as it will panic if its called after the test has finished
			// require.NoError(t, err)
			if err != nil {
				return
			}
			// Before use, a handshake must be performed on the incoming net.Conn.
			_, _, _, err = gossh.NewServerConn(tcpConn, config)
			// DONT "require" in here as it will panic if its called after the test has finished
			// require.NoError(t, err)
			if err != nil {
				continue
			}

			s.mu.Lock()
			s.connectionsCount++
			s.mu.Unlock()
		}
	}()

	return nil
}

func (s *testServer) Stop() error {
	return s.listener.Close()
}

func TestConnectionCount(t *testing.T) {
	tests := []struct {
		name        string
		connections int
		expectedIDs []string
	}{
		{
			name:        "single connection",
			connections: 1,
			expectedIDs: []string{"1"},
		},
		{
			name:        "two connections",
			connections: 2,
			expectedIDs: []string{"1", "2"},
		},
		{
			name:        "five connections",
			connections: 5,
			expectedIDs: []string{"1", "2", "3", "4", "5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &testServer{}
			require.NoError(t, srv.Start())
			defer func() { _ = srv.Stop() }()

			cfg := ssh.DefaultConfig()
			cfg.Port = 2200
			cfg.URL = mustParseURL("0.0.0.0")
			cfg.PDC = pdc.Config{
				HostedGrafanaID: "123",
			}
			// strip out some config to make the ssh handshake succeed
			cfg.SSHFlags = []string{
				"-o UserKnownHostsFile=/dev/null",
				"-o StrictHostKeyChecking=no",
			}
			// create a config with the number of connections per test case
			cfg.Connections = tt.connections

			// create a live client
			logger := log.NewNopLogger()
			mClient := mockPDCClient{}
			km := ssh.NewKeyManager(cfg, logger, mClient)
			client := ssh.NewClient(cfg, logger, km)

			ctx := context.Background()

			// start the client
			err := client.StartAsync(ctx)
			require.NoError(t, err)

			// make sure the client runs
			err = client.AwaitRunning(ctx)
			require.NoError(t, err)

			// Wait for connections to initialize
			time.Sleep(500 * time.Millisecond)

			srv.mu.Lock()
			actualConnections := srv.connectionsCount
			srv.mu.Unlock()
			require.Equal(t, tt.connections, actualConnections)

			// Cleanup
			client.StopAsync()
			_ = client.AwaitTerminated(ctx)
		})
	}
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

type assertFn func(t *testing.T, s string)

func TestLoggerWriterAdapter(t *testing.T) {

	testcases := []struct {
		name      string
		input     []byte
		callback  func(t *testing.T)
		assertFns []assertFn
	}{
		{
			name:  "pass through",
			input: []byte("passthrough"),
			assertFns: []assertFn{
				func(t *testing.T, s string) {
					assert.Equal(t, "passthrough", s)
				},
			},
		},
		{
			name:  "split on \r\n",
			input: []byte("hello\r\nworld"),
			assertFns: []assertFn{
				func(t *testing.T, s string) {
					assert.Equal(t, "hello", s)
				},
				func(t *testing.T, s string) {
					assert.Equal(t, "world", s)
				},
			},
		},
		{
			name:      "call callback on successful connection",
			input:     []byte(ssh.SuccessfulConnectionResponse),
			assertFns: nil,
			callback: func(t *testing.T) {
				assert.True(t, true, true)
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			if tc.callback == nil {
				tc.callback = func(t *testing.T) {
					assert.FailNow(t, "should not be called")
				}
			}

			cb := func() {
				tc.callback(t)
			}

			logger := newLoggerWithAssertFn(t, tc.assertFns)
			l := ssh.NewLoggerWriterAdapter(logger, "debug", nil, cb)
			_, _ = l.Write(tc.input)

		})
	}
}

type assertLogger struct {
	// iterate through assertFns, call one each time Write is called
	assertFns []assertFn
	t         *testing.T
	i         int
}

func (a *assertLogger) Log(keyvals ...interface{}) error {
	// items are "level" <level> "msg" <message>. We want <message>.
	kv := keyvals[3]
	s := kv.(string)
	if len(a.assertFns)-1 >= a.i {
		a.assertFns[a.i](a.t, s)
		a.i++
	}
	return nil
}

func newLoggerWithAssertFn(t *testing.T, fs []assertFn) log.Logger {
	return &assertLogger{
		assertFns: fs,
		t:         t,
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
