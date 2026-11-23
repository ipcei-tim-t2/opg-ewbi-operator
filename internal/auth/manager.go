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
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/neonephos-katalis/opg-ewbi-operator/api/operator/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClusterOidcConfig encapsulates connection parameters and OIDC credentials extracted from a Kubeconfig.
type ClusterOidcConfig struct {
	// HostApiServerUrl is the API server URL extracted from clusters[].cluster.server.
	HostApiServerUrl string

	// CAData is the PEM-encoded CA certificate extracted from clusters[].cluster.certificate-authority-data.
	CAData []byte

	// InsecureSkipTLSVerify indicates if TLS verification is skipped for the cluster connection.
	InsecureSkipTLSVerify bool

	// TokenRequestOpts contains the parameters needed by TokenManager to request ephemeral tokens.
	TokenRequestOpts TokenRequestOptions
}

// TokenManager manages the in-memory cache and lifecycle of OIDC tokens for Federations.
// Raw JWT tokens are NEVER stored in Kubernetes Status or on disk, preserving Zero-Trust security.
type TokenManager struct {
	client OidcClient
	mu     sync.RWMutex
	tokens map[string]*TokenResponse
}

// DefaultTokenManager is the global token manager instance used across controllers.
var DefaultTokenManager = NewTokenManager(NewHTTPTokenClient(nil))

// NewTokenManager creates a new instance of TokenManager.
func NewTokenManager(client OidcClient) *TokenManager {
	return &TokenManager{
		client: client,
		tokens: make(map[string]*TokenResponse),
	}
}

// GetToken returns a valid OIDC Access Token for the given Federation resource.
// If a cached token is still valid (has not reached its 80% refresh mark), it is returned.
// Otherwise, it resolves credentials (either from fed.Spec.FederationData.K8sOptions.Auth or from
// the referenced Kubeconfig Secret) and requests a new token from the IdP.
func (m *TokenManager) GetToken(ctx context.Context, localClient client.Client, fed *v1beta1.Federation) (*TokenResponse, error) {
	if fed == nil || fed.Spec.FederationData == nil || fed.Spec.FederationData.K8sOptions == nil {
		return nil, fmt.Errorf("federation has no k8sOptions configured")
	}

	k8sOpts := fed.Spec.FederationData.K8sOptions
	cacheKey := fed.GetNamespace() + "/" + fed.GetName()
	now := time.Now()

	// 1. Check if we have a valid cached token that has not reached 80% TTL
	m.mu.RLock()
	cached, exists := m.tokens[cacheKey]
	m.mu.RUnlock()

	if exists && cached != nil {
		remainingUntilRefresh := CalculateRefreshDuration(cached.IssuedAt, cached.Expiry, now, DefaultRefreshFactor)
		if remainingUntilRefresh > 0 && now.Before(cached.Expiry) {
			return cached, nil
		}
	}

	// 2. Fetch a fresh token
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check cache in case another goroutine just refreshed it
	cached, exists = m.tokens[cacheKey]
	if exists && cached != nil {
		remainingUntilRefresh := CalculateRefreshDuration(cached.IssuedAt, cached.Expiry, now, DefaultRefreshFactor)
		if remainingUntilRefresh > 0 && now.Before(cached.Expiry) {
			return cached, nil
		}
	}

	var reqOpts TokenRequestOptions

	if k8sOpts.Auth != nil {
		// Path A: Direct CRD Spec-based OIDC Auth
		clientSecret, err := ResolveSecretKey(ctx, localClient, fed.GetNamespace(), k8sOpts.Auth.ClientSecretRef)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve clientSecretRef for federation %q: %w", cacheKey, err)
		}

		reqOpts = TokenRequestOptions{
			TokenURL:     k8sOpts.Auth.TokenUrl,
			ClientID:     k8sOpts.Auth.ClientId,
			ClientSecret: clientSecret,
			Audience:     k8sOpts.Auth.Audience,
			Scopes:       k8sOpts.Auth.Scopes,
		}
	} else if k8sOpts.SecretName != "" {
		// Path B: Kubeconfig Ingestion with In-Memory Session Handover
		kubeBytes, err := ResolveSecretBytes(ctx, localClient, fed.Namespace, k8sOpts.SecretName, "kubeconfig")
		if err != nil {
			var fallbackErr error
			kubeBytes, fallbackErr = ResolveSecretBytes(ctx, localClient, fed.Namespace, k8sOpts.SecretName, "config")
			if fallbackErr != nil {
				kubeBytes, fallbackErr = ResolveSecretBytes(ctx, localClient, fed.Namespace, k8sOpts.SecretName, "kubeconfig.yaml")
				if fallbackErr != nil {
					return nil, fmt.Errorf("failed to retrieve kubeconfig from secret %s/%s: %w", fed.Namespace, k8sOpts.SecretName, err)
				}
			}
		}

		oidcCfg, err := ExtractOidcClusterConfig(ctx, localClient, fed.Namespace, kubeBytes, k8sOpts.ContextName, k8sOpts.SecretName)
		if err != nil {
			return nil, fmt.Errorf("failed to extract OIDC config from kubeconfig for federation %q: %w", cacheKey, err)
		}
		if oidcCfg == nil {
			return nil, fmt.Errorf("kubeconfig in secret %s/%s does not contain OIDC auth-provider configuration", fed.Namespace, k8sOpts.SecretName)
		}

		reqOpts = oidcCfg.TokenRequestOpts
	} else {
		return nil, fmt.Errorf("federation %s/%s does not have OIDC Auth or SecretName configured", fed.GetNamespace(), fed.GetName())
	}

	resp, err := m.client.RequestToken(ctx, reqOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain token from IdP for federation %q: %w", cacheKey, err)
	}

	m.tokens[cacheKey] = resp
	return resp, nil
}

// Invalidate removes any cached token for the given federation key (e.g. upon deletion).
func (m *TokenManager) Invalidate(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, key)
}

// IsOidcConfigured checks whether the Federation resource is configured to use dynamic OIDC M2M authentication,
// either directly via fed.Spec.FederationData.K8sOptions.Auth or through an OIDC auth-provider
// in the referenced Kubeconfig Secret.
func IsOidcConfigured(ctx context.Context, localClient client.Client, fed *v1beta1.Federation) (bool, error) {
	if fed == nil || fed.Spec.FederationData == nil || fed.Spec.FederationData.K8sOptions == nil {
		return false, nil
	}

	k8sOpts := fed.Spec.FederationData.K8sOptions
	// Direct CRD Spec configuration
	if k8sOpts.Auth != nil {
		return true, nil
	}

	// Kubeconfig Secret reference
	if k8sOpts.SecretName != "" {
		kubeBytes, err := ResolveSecretBytes(ctx, localClient, fed.Namespace, k8sOpts.SecretName, "kubeconfig")
		if err != nil {
			var fallbackErr error
			kubeBytes, fallbackErr = ResolveSecretBytes(ctx, localClient, fed.Namespace, k8sOpts.SecretName, "config")
			if fallbackErr != nil {
				kubeBytes, fallbackErr = ResolveSecretBytes(ctx, localClient, fed.Namespace, k8sOpts.SecretName, "kubeconfig.yaml")
				if fallbackErr != nil {
					return false, nil
				}
			}
		}

		cfg, err := ExtractOidcClusterConfig(ctx, localClient, fed.Namespace, kubeBytes, k8sOpts.ContextName, k8sOpts.SecretName)
		if err != nil {
			return false, err
		}
		return cfg != nil, nil
	}

	return false, nil
}

// ExtractOidcClusterConfig parses a Kubeconfig YAML and checks if the active/selected user uses an OIDC auth-provider.
// If it is an OIDC configuration, it extracts the target cluster endpoint, CA data, and token request options.
// If it is a traditional static kubeconfig (e.g. static token, client certificates), it returns nil, nil.
func ExtractOidcClusterConfig(
	ctx context.Context,
	localClient client.Client,
	namespace string,
	kubeconfigBytes []byte,
	contextName string,
	parentSecretName string,
) (*ClusterOidcConfig, error) {
	if len(kubeconfigBytes) == 0 {
		return nil, fmt.Errorf("empty kubeconfig data")
	}

	config, err := clientcmd.Load(kubeconfigBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig YAML: %w", err)
	}

	// 1. Resolve Context
	targetContext := contextName
	if targetContext == "" {
		targetContext = config.CurrentContext
	}
	if targetContext == "" && len(config.Contexts) == 1 {
		for name := range config.Contexts {
			targetContext = name
			break
		}
	}

	ctxObj, ok := config.Contexts[targetContext]
	if !ok || ctxObj == nil {
		return nil, fmt.Errorf("context %q not found in kubeconfig", targetContext)
	}

	// 2. Resolve Cluster
	clusterObj, ok := config.Clusters[ctxObj.Cluster]
	if !ok || clusterObj == nil {
		return nil, fmt.Errorf("cluster %q referenced by context %q not found in kubeconfig", ctxObj.Cluster, targetContext)
	}

	// 3. Resolve AuthInfo
	authInfo, ok := config.AuthInfos[ctxObj.AuthInfo]
	if !ok || authInfo == nil {
		return nil, fmt.Errorf("user %q referenced by context %q not found in kubeconfig", ctxObj.AuthInfo, targetContext)
	}

	// Check if this user uses OIDC auth-provider
	if authInfo.AuthProvider == nil || authInfo.AuthProvider.Config == nil {
		return nil, nil
	}

	authCfg := authInfo.AuthProvider.Config
	isOidc := strings.EqualFold(authInfo.AuthProvider.Name, "oidc") ||
		authCfg["idp-issuer-url"] != "" || authCfg["issuer-url"] != "" ||
		authCfg["token-url"] != "" || authCfg["idp-token-url"] != ""

	if !isOidc {
		return nil, nil
	}

	// 4. Resolve Token Endpoint URL
	tokenURL := authCfg["token-url"]
	if tokenURL == "" {
		tokenURL = authCfg["idp-token-url"]
	}
	if tokenURL == "" {
		issuer := authCfg["idp-issuer-url"]
		if issuer == "" {
			issuer = authCfg["issuer-url"]
		}
		if issuer != "" {
			if strings.HasSuffix(issuer, "/protocol/openid-connect/token") {
				tokenURL = issuer
			} else {
				tokenURL = strings.TrimSuffix(issuer, "/") + "/protocol/openid-connect/token"
			}
		}
	}
	if tokenURL == "" {
		return nil, fmt.Errorf("kubeconfig OIDC auth-provider requires idp-issuer-url or token-url")
	}

	// 5. Resolve Client ID
	clientID := authCfg["client-id"]
	if clientID == "" {
		clientID = authCfg["clientID"]
	}
	if clientID == "" {
		return nil, fmt.Errorf("kubeconfig OIDC auth-provider requires client-id")
	}

	// 6. Resolve Client Secret
	clientSecret := authCfg["client-secret"]
	if clientSecret == "" {
		secretRef := authCfg["client-secret-name"]
		if secretRef == "" {
			secretRef = authCfg["client-secret-ref"]
		}
		if secretRef != "" && localClient != nil {
			secretKey := authCfg["client-secret-key"]
			if secretKey == "" {
				secretKey = "client-secret"
			}
			resolved, err := ResolveSecretKey(ctx, localClient, namespace, corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: secretRef},
				Key:                  secretKey,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to resolve client-secret from referenced secret %s/%s: %w", namespace, secretRef, err)
			}
			clientSecret = resolved
		} else if parentSecretName != "" && localClient != nil {
			secretBytes, err := ResolveSecretBytes(ctx, localClient, namespace, parentSecretName, "client-secret")
			if err == nil && len(secretBytes) > 0 {
				clientSecret = string(secretBytes)
			}
		}
	}
	if clientSecret == "" {
		return nil, fmt.Errorf("kubeconfig OIDC auth-provider requires client-secret (or client-secret-name reference)")
	}

	// 7. Resolve Audience and Scopes
	audience := authCfg["audience"]
	if audience == "" {
		audience = authCfg["idp-audience"]
	}

	scopesRaw := authCfg["scopes"]
	if scopesRaw == "" {
		scopesRaw = authCfg["extra-scopes"]
	}
	if scopesRaw == "" {
		scopesRaw = authCfg["scope"]
	}
	var scopes []string
	if scopesRaw != "" {
		for _, s := range strings.FieldsFunc(scopesRaw, func(r rune) bool {
			return r == ',' || r == ' '
		}) {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				scopes = append(scopes, trimmed)
			}
		}
	}
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}

	// 8. Resolve CA Data
	caData := clusterObj.CertificateAuthorityData
	if len(caData) == 0 && clusterObj.CertificateAuthority != "" {
		if fileBytes, err := os.ReadFile(clusterObj.CertificateAuthority); err == nil {
			caData = fileBytes
		}
	}

	return &ClusterOidcConfig{
		HostApiServerUrl:      clusterObj.Server,
		CAData:                caData,
		InsecureSkipTLSVerify: clusterObj.InsecureSkipTLSVerify,
		TokenRequestOpts: TokenRequestOptions{
			TokenURL:     tokenURL,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Audience:     audience,
			Scopes:       scopes,
		},
	}, nil
}
