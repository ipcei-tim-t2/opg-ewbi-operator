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

package auth

import (
	"context"
	"testing"
	"time"

	"github.com/neonephos-katalis/opg-ewbi-operator/api/operator/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const sampleOidcKubeconfigDirect = `
apiVersion: v1
clusters:
- cluster:
    server: https://host-k8s:6443
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg==
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
        idp-issuer-url: https://keycloak.example.com/realms/host
        client-id: guest-operator
        client-secret: my-direct-secret
        audience: https://host-k8s:6443
        extra-scopes: "openid,profile,email"
`

const sampleOidcKubeconfigReferenced = `
apiVersion: v1
clusters:
- cluster:
    server: https://host-k8s:6443
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
        idp-issuer-url: https://keycloak.example.com/realms/host
        client-id: guest-operator
        client-secret-name: eso-synced-secret
        client-secret-key: token-secret
`

const sampleOidcKubeconfigSibling = `
apiVersion: v1
clusters:
- cluster:
    server: https://host-k8s:6443
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
        token-url: https://keycloak.example.com/realms/host/protocol/openid-connect/token
        client-id: guest-operator
`

const sampleStaticKubeconfig = `
apiVersion: v1
clusters:
- cluster:
    server: https://host-k8s:6443
  name: host-cluster
contexts:
- context:
    cluster: host-cluster
    user: static-sa
  name: host-context
current-context: host-context
kind: Config
users:
- name: static-sa
  user:
    token: static-token-value
`

type mockOidcClient struct {
	callCount int
	tokenResp *TokenResponse
	err       error
}

func (m *mockOidcClient) RequestToken(ctx context.Context, opts TokenRequestOptions) (*TokenResponse, error) {
	m.callCount++
	if m.err != nil {
		return nil, m.err
	}
	resp := *m.tokenResp
	resp.IssuedAt = time.Now()
	resp.Expiry = resp.IssuedAt.Add(time.Duration(resp.ExpiresIn) * time.Second)
	return &resp, nil
}

func TestTokenManager(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1beta1.AddToScheme(scheme))

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"client-secret": []byte("valid-secret"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	fed := &v1beta1.Federation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fed-test",
			Namespace: "test-ns",
		},
		Spec: v1beta1.FederationSpec{
			FederationData: &v1beta1.FederationData{
				K8sOptions: &v1beta1.K8sOptions{
					Namespace: "host-ns",
					Auth: &v1beta1.OidcAuthOptions{
						TokenUrl: "http://idp.local/token",
						ClientId: "client-1",
						ClientSecretRef: corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "test-secret"},
							Key:                  "client-secret",
						},
						Audience: "aud-host",
					},
				},
			},
		},
	}

	ctx := context.Background()

	t.Run("Fetches token and caches it on first call", func(t *testing.T) {
		mockClient := &mockOidcClient{
			tokenResp: &TokenResponse{
				AccessToken: "token-1",
				TokenType:   "Bearer",
				ExpiresIn:   300,
			},
		}
		tm := NewTokenManager(mockClient)

		// Call 1: Should call mockClient
		resp1, err := tm.GetToken(ctx, fakeClient, fed)
		require.NoError(t, err)
		assert.Equal(t, "token-1", resp1.AccessToken)
		assert.Equal(t, 1, mockClient.callCount)

		// Call 2: Should use cached token, no new request
		resp2, err := tm.GetToken(ctx, fakeClient, fed)
		require.NoError(t, err)
		assert.Equal(t, "token-1", resp2.AccessToken)
		assert.Equal(t, 1, mockClient.callCount)
	})

	t.Run("Invalidate clears cache forcing new request", func(t *testing.T) {
		mockClient := &mockOidcClient{
			tokenResp: &TokenResponse{
				AccessToken: "token-new",
				TokenType:   "Bearer",
				ExpiresIn:   300,
			},
		}
		tm := NewTokenManager(mockClient)

		_, err := tm.GetToken(ctx, fakeClient, fed)
		require.NoError(t, err)
		assert.Equal(t, 1, mockClient.callCount)

		tm.Invalidate("test-ns/fed-test")

		_, err = tm.GetToken(ctx, fakeClient, fed)
		require.NoError(t, err)
		assert.Equal(t, 2, mockClient.callCount)
	})

	t.Run("Fetches token via Kubeconfig Secret and caches it in-memory", func(t *testing.T) {
		kubeSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "hybrid-kubeconfig-secret",
				Namespace: "test-ns",
			},
			Data: map[string][]byte{
				"kubeconfig": []byte(sampleOidcKubeconfigDirect),
			},
		}

		hybridClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(kubeSecret).
			Build()

		hybridFed := &v1beta1.Federation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "fed-hybrid-test",
				Namespace: "test-ns",
			},
			Spec: v1beta1.FederationSpec{
				FederationData: &v1beta1.FederationData{
					K8sOptions: &v1beta1.K8sOptions{
						Namespace:   "host-ns",
						SecretName:  "hybrid-kubeconfig-secret",
						ContextName: "host-context",
					},
				},
			},
		}

		mockClient := &mockOidcClient{
			tokenResp: &TokenResponse{
				AccessToken: "hybrid-jwt-token",
				TokenType:   "Bearer",
				ExpiresIn:   300,
			},
		}
		tm := NewTokenManager(mockClient)

		// First call: extracts OIDC config from kubeconfig and fetches token via mockClient
		resp1, err := tm.GetToken(ctx, hybridClient, hybridFed)
		require.NoError(t, err)
		assert.Equal(t, "hybrid-jwt-token", resp1.AccessToken)
		assert.Equal(t, 1, mockClient.callCount)

		// Second call: served from in-memory cache
		resp2, err := tm.GetToken(ctx, hybridClient, hybridFed)
		require.NoError(t, err)
		assert.Equal(t, "hybrid-jwt-token", resp2.AccessToken)
		assert.Equal(t, 1, mockClient.callCount, "Second call must hit in-memory RAM cache, 0 external calls")
	})
}

func TestExtractOidcClusterConfig(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	esoSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "eso-synced-secret",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"token-secret": []byte("resolved-secret-value"),
		},
	}

	parentSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "parent-kube-secret",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"kubeconfig":    []byte(sampleOidcKubeconfigSibling),
			"client-secret": []byte("sibling-secret-value"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(esoSecret, parentSecret).
		Build()

	ctx := context.Background()

	t.Run("Extract from kubeconfig with direct client-secret", func(t *testing.T) {
		cfg, err := ExtractOidcClusterConfig(ctx, fakeClient, "test-ns", []byte(sampleOidcKubeconfigDirect), "host-context", "")
		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, "https://host-k8s:6443", cfg.HostApiServerUrl)
		assert.Equal(t, "https://keycloak.example.com/realms/host/protocol/openid-connect/token", cfg.TokenRequestOpts.TokenURL)
		assert.Equal(t, "guest-operator", cfg.TokenRequestOpts.ClientID)
		assert.Equal(t, "my-direct-secret", cfg.TokenRequestOpts.ClientSecret)
		assert.Equal(t, "https://host-k8s:6443", cfg.TokenRequestOpts.Audience)
		assert.Equal(t, []string{"openid", "profile", "email"}, cfg.TokenRequestOpts.Scopes)
		assert.False(t, cfg.InsecureSkipTLSVerify)
		assert.NotEmpty(t, cfg.CAData)
	})

	t.Run("Extract from kubeconfig with referenced external secret", func(t *testing.T) {
		cfg, err := ExtractOidcClusterConfig(ctx, fakeClient, "test-ns", []byte(sampleOidcKubeconfigReferenced), "host-context", "")
		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, "https://host-k8s:6443", cfg.HostApiServerUrl)
		assert.Equal(t, "resolved-secret-value", cfg.TokenRequestOpts.ClientSecret)
		assert.True(t, cfg.InsecureSkipTLSVerify)
	})

	t.Run("Extract from kubeconfig with sibling secret in parent secret", func(t *testing.T) {
		cfg, err := ExtractOidcClusterConfig(ctx, fakeClient, "test-ns", []byte(sampleOidcKubeconfigSibling), "host-context", "parent-kube-secret")
		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, "https://host-k8s:6443", cfg.HostApiServerUrl)
		assert.Equal(t, "sibling-secret-value", cfg.TokenRequestOpts.ClientSecret)
	})

	t.Run("Static kubeconfig returns nil, nil without error", func(t *testing.T) {
		cfg, err := ExtractOidcClusterConfig(ctx, fakeClient, "test-ns", []byte(sampleStaticKubeconfig), "host-context", "")
		require.NoError(t, err)
		assert.Nil(t, cfg, "Legacy static kubeconfig must return nil so caller falls back to standard clientcmd")
	})

	t.Run("Non-existent context returns error", func(t *testing.T) {
		_, err := ExtractOidcClusterConfig(ctx, fakeClient, "test-ns", []byte(sampleOidcKubeconfigDirect), "non-existent-ctx", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context \"non-existent-ctx\" not found")
	})
}

func TestIsOidcConfigured(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1beta1.AddToScheme(scheme))

	oidcSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-kube-secret",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"kubeconfig": []byte(sampleOidcKubeconfigDirect),
		},
	}

	staticSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "static-kube-secret",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"kubeconfig": []byte(sampleStaticKubeconfig),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(oidcSecret, staticSecret).
		Build()

	ctx := context.Background()

	t.Run("Returns true when Spec.Auth is configured", func(t *testing.T) {
		fed := &v1beta1.Federation{
			Spec: v1beta1.FederationSpec{
				FederationData: &v1beta1.FederationData{
					K8sOptions: &v1beta1.K8sOptions{
						Auth: &v1beta1.OidcAuthOptions{
							TokenUrl: "http://example.com/token",
							ClientId: "client-id",
						},
					},
				},
			},
		}
		isOidc, err := IsOidcConfigured(ctx, fakeClient, fed)
		require.NoError(t, err)
		assert.True(t, isOidc)
	})

	t.Run("Returns true when Kubeconfig Secret contains OIDC auth-provider", func(t *testing.T) {
		fed := &v1beta1.Federation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test-ns",
				Name:      "fed-hybrid",
			},
			Spec: v1beta1.FederationSpec{
				FederationData: &v1beta1.FederationData{
					K8sOptions: &v1beta1.K8sOptions{
						SecretName:  "oidc-kube-secret",
						ContextName: "host-context",
					},
				},
			},
		}
		isOidc, err := IsOidcConfigured(ctx, fakeClient, fed)
		require.NoError(t, err)
		assert.True(t, isOidc)
	})

	t.Run("Returns false when Kubeconfig Secret contains static credentials", func(t *testing.T) {
		fed := &v1beta1.Federation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test-ns",
				Name:      "fed-static",
			},
			Spec: v1beta1.FederationSpec{
				FederationData: &v1beta1.FederationData{
					K8sOptions: &v1beta1.K8sOptions{
						SecretName:  "static-kube-secret",
						ContextName: "host-context",
					},
				},
			},
		}
		isOidc, err := IsOidcConfigured(ctx, fakeClient, fed)
		require.NoError(t, err)
		assert.False(t, isOidc)
	})

	t.Run("Returns false when neither Auth nor SecretName is configured", func(t *testing.T) {
		fed := &v1beta1.Federation{
			Spec: v1beta1.FederationSpec{
				FederationData: &v1beta1.FederationData{
					K8sOptions: &v1beta1.K8sOptions{},
				},
			},
		}
		isOidc, err := IsOidcConfigured(ctx, fakeClient, fed)
		require.NoError(t, err)
		assert.False(t, isOidc)
	})
}
