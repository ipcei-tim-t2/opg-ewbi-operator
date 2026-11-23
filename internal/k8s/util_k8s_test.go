/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package k8s

import (
	"context"
	"testing"
	"time"

	"github.com/neonephos-katalis/opg-ewbi-operator/api/operator/v1beta1"
	"github.com/neonephos-katalis/opg-ewbi-operator/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type mockK8sOidcClient struct {
	accessToken string
}

func (m *mockK8sOidcClient) RequestToken(ctx context.Context, opts auth.TokenRequestOptions) (*auth.TokenResponse, error) {
	now := time.Now()
	return &auth.TokenResponse{
		AccessToken: m.accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   300,
		IssuedAt:    now,
		Expiry:      now.Add(300 * time.Second),
	}, nil
}

func TestGetKubeconfigFromSecret(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	t.Run("Finds kubeconfig under standard key 'kubeconfig'", func(t *testing.T) {
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "sec1", Namespace: "default"},
			Data:       map[string][]byte{"kubeconfig": []byte("data1")},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
		data, err := GetKubeconfigFromSecret(context.Background(), c, "sec1", "default")
		require.NoError(t, err)
		assert.Equal(t, []byte("data1"), data)
	})

	t.Run("Finds kubeconfig under fallback key 'config'", func(t *testing.T) {
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "sec2", Namespace: "default"},
			Data:       map[string][]byte{"config": []byte("data2")},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
		data, err := GetKubeconfigFromSecret(context.Background(), c, "sec2", "default")
		require.NoError(t, err)
		assert.Equal(t, []byte("data2"), data)
	})

	t.Run("Returns error when secret does not exist", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		_, err := GetKubeconfigFromSecret(context.Background(), c, "missing", "default")
		require.Error(t, err)
	})
}

func TestBuildHostClient_HybridArchitecture(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1beta1.AddToScheme(scheme))

	origTM := auth.DefaultTokenManager
	auth.DefaultTokenManager = auth.NewTokenManager(&mockK8sOidcClient{
		accessToken: "mock-hybrid-access-token",
	})
	defer func() { auth.DefaultTokenManager = origTM }()

	kubeSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "hybrid-sec",
			Namespace: "guest-ns",
		},
		Data: map[string][]byte{
			"kubeconfig": []byte(`
apiVersion: v1
clusters:
- cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
  name: host-cluster
contexts:
- context:
    cluster: host-cluster
    user: oidc-user
  name: host-context
current-context: host-context
kind: Config
users:
- name: oidc-user
  user:
    auth-provider:
      name: oidc
      config:
        idp-issuer-url: https://keycloak.test/realms/host
        client-id: guest-client
        client-secret: secret-val
`),
		},
	}

	fed := &v1beta1.Federation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fed-hybrid-client",
			Namespace: "guest-ns",
		},
		Spec: v1beta1.FederationSpec{
			FederationData: &v1beta1.FederationData{
				K8sOptions: &v1beta1.K8sOptions{
					Namespace:   "host-ns",
					SecretName:  "hybrid-sec",
					ContextName: "host-context",
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(kubeSecret, fed).
		Build()

	ctx := context.Background()

	k8sClient, dynClient, err := buildHostClient(ctx, fed, fakeClient, scheme)
	require.NoError(t, err)
	assert.NotNil(t, k8sClient, "K8s client must be created successfully")
	assert.NotNil(t, dynClient, "Dynamic client must be created successfully")
}
