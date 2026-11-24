package kubernetes

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestDeploymentTemplates_SharedConfiguration(t *testing.T) {
	t.Parallel()

	legacy := normalizedDeployment(t, "pdc-agent-deployment.yaml",
		map[string]string{"CLUSTER": "cluster"},
		map[string]string{"-cluster": "$(CLUSTER)"},
	)
	fqdn := normalizedDeployment(t, "pdc-agent-deployment-fqdn.yaml",
		map[string]string{"API_FQDN": "api-fqdn", "GATEWAY_FQDN": "gateway-fqdn"},
		map[string]string{"-api-fqdn": "$(API_FQDN)", "-gateway-fqdn": "$(GATEWAY_FQDN)"},
	)

	require.Equal(t, legacy, fqdn, "deployment templates must differ only in endpoint configuration")
}

func normalizedDeployment(t *testing.T, filename string, endpointEnv, endpointArgs map[string]string) map[string]any {
	t.Helper()

	data, err := os.ReadFile(filename)
	require.NoError(t, err)

	var deployment map[string]any
	require.NoError(t, yaml.Unmarshal(data, &deployment), filename)

	containers := deployment["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)
	var agent map[string]any
	for _, raw := range containers {
		container := raw.(map[string]any)
		if container["name"] == "grafana-pdc-agent" {
			require.Nil(t, agent, "%s contains duplicate agent containers", filename)
			agent = container
		}
	}
	require.NotNil(t, agent, "%s must contain the agent container", filename)

	var sharedEnv []any
	seenEnv := make(map[string]bool)
	for _, raw := range agent["env"].([]any) {
		entry := raw.(map[string]any)
		name := entry["name"].(string)
		key, endpoint := endpointEnv[name]
		if !endpoint {
			sharedEnv = append(sharedEnv, raw)
			continue
		}

		require.False(t, seenEnv[name], "%s repeats endpoint variable %s", filename, name)
		seenEnv[name] = true
		require.Equal(t, map[string]any{
			"name": name,
			"valueFrom": map[string]any{
				"secretKeyRef": map[string]any{"name": "grafana-pdc-agent", "key": key},
			},
		}, entry, "%s endpoint variable %s", filename, name)
	}
	require.Len(t, seenEnv, len(endpointEnv), "%s is missing endpoint variables", filename)
	agent["env"] = sharedEnv

	args := agent["args"].([]any)
	var sharedArgs []any
	seenArgs := make(map[string]bool)
	for index := 0; index < len(args); index++ {
		flag := args[index].(string)
		value, endpoint := endpointArgs[flag]
		if !endpoint {
			sharedArgs = append(sharedArgs, args[index])
			continue
		}

		require.False(t, seenArgs[flag], "%s repeats endpoint flag %s", filename, flag)
		seenArgs[flag] = true
		require.Less(t, index+1, len(args), "%s is missing the value for %s", filename, flag)
		require.Equal(t, value, args[index+1], "%s endpoint flag %s", filename, flag)
		index++
	}
	require.Len(t, seenArgs, len(endpointArgs), "%s is missing endpoint flags", filename)
	agent["args"] = sharedArgs

	return deployment
}
