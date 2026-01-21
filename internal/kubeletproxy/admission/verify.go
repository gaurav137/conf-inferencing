package admission

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

const (
	// PolicyAnnotation is the annotation key for the signed policy (base64-encoded JSON)
	PolicyAnnotation = "kubelet-proxy.io/policy"

	// SignatureAnnotation is the annotation key for the policy signature
	SignatureAnnotation = "kubelet-proxy.io/signature"
)

// Policy defines what a pod is allowed to do
// This is extracted from the pod spec at signing time and verified at admission time
type Policy struct {
	// AllowedImages is a list of allowed container image patterns (supports wildcards)
	AllowedImages []string `json:"allowedImages,omitempty"`

	// AllowedServiceAccounts is a list of allowed service account names
	AllowedServiceAccounts []string `json:"allowedServiceAccounts,omitempty"`

	// AllowHostNetwork indicates whether hostNetwork is allowed
	AllowHostNetwork bool `json:"allowHostNetwork,omitempty"`

	// AllowHostPID indicates whether hostPID is allowed
	AllowHostPID bool `json:"allowHostPID,omitempty"`

	// AllowHostIPC indicates whether hostIPC is allowed
	AllowHostIPC bool `json:"allowHostIPC,omitempty"`

	// AllowPrivileged indicates whether privileged containers are allowed
	AllowPrivileged bool `json:"allowPrivileged,omitempty"`

	// AllowedCapabilities lists allowed Linux capabilities
	AllowedCapabilities []string `json:"allowedCapabilities,omitempty"`

	// AllowedVolumeMounts lists allowed volume mount paths (supports wildcards)
	AllowedVolumeMounts []string `json:"allowedVolumeMounts,omitempty"`

	// AllowedNodeSelectors lists allowed node selector key-value pairs
	AllowedNodeSelectors map[string]string `json:"allowedNodeSelectors,omitempty"`
}

// SignatureVerificationController verifies pod policy signatures
type SignatureVerificationController struct {
	publicKey crypto.PublicKey
	certPath  string
	logger    *log.Logger
}

// NewSignatureVerificationController creates a new signature verification controller
func NewSignatureVerificationController(certPath string) (*SignatureVerificationController, error) {
	logger := log.New(os.Stdout, "[signature-verification] ", log.LstdFlags|log.Lmicroseconds)

	publicKey, err := loadPublicKey(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load public key from %s: %w", certPath, err)
	}

	logger.Printf("Loaded public key from %s", certPath)

	return &SignatureVerificationController{
		publicKey: publicKey,
		certPath:  certPath,
		logger:    logger,
	}, nil
}

// Name returns the name of the controller
func (c *SignatureVerificationController) Name() string {
	return "signature-verification"
}

// Admit verifies the pod policy signature and checks if the pod matches the policy
func (c *SignatureVerificationController) Admit(req *Request) *Decision {
	// Allow all pods in kube-system namespace without signature verification
	if req.Namespace == "kube-system" {
		c.logger.Printf("Pod %s/%s allowed: kube-system namespace is exempt from signature verification", req.Namespace, req.Name)
		return Allow("kube-system namespace is exempt from signature verification")
	}

	// Get the policy and signature from annotations
	policyStr, hasPolicy := c.getAnnotation(req.Pod, PolicyAnnotation)
	if !hasPolicy {
		c.logger.Printf("Pod %s/%s has no policy annotation", req.Namespace, req.Name)
		return Deny("pod policy required but not found (missing annotation: " + PolicyAnnotation + ")")
	}

	signature, hasSignature := c.getAnnotation(req.Pod, SignatureAnnotation)
	if !hasSignature {
		c.logger.Printf("Pod %s/%s has no signature annotation", req.Namespace, req.Name)
		return Deny("pod signature required but not found (missing annotation: " + SignatureAnnotation + ")")
	}

	// Decode the policy from base64
	policyBytes, err := base64.StdEncoding.DecodeString(policyStr)
	if err != nil {
		c.logger.Printf("Invalid policy encoding for %s/%s: %v", req.Namespace, req.Name, err)
		return Deny("invalid policy encoding: must be base64")
	}

	var policy Policy
	if err := json.Unmarshal(policyBytes, &policy); err != nil {
		c.logger.Printf("Invalid policy JSON for %s/%s: %v", req.Namespace, req.Name, err)
		return Deny(fmt.Sprintf("invalid policy JSON: %v", err))
	}

	// Verify the signature on the base64-encoded policy (what was actually signed)
	// We sign the base64 string, not the decoded bytes, for consistency
	policyHash := sha256.Sum256([]byte(policyStr))
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		c.logger.Printf("Invalid signature encoding for %s/%s: %v", req.Namespace, req.Name, err)
		return Deny("invalid signature encoding: must be base64")
	}

	if err := c.verifySignature(policyHash[:], signatureBytes); err != nil {
		c.logger.Printf("Policy signature verification failed for %s/%s: %v", req.Namespace, req.Name, err)
		return Deny(fmt.Sprintf("policy signature verification failed: %v", err))
	}

	c.logger.Printf("Policy signature verified for pod %s/%s", req.Namespace, req.Name)

	// Check if the pod matches the policy
	if err := c.checkPodAgainstPolicy(req.Pod, &policy); err != nil {
		c.logger.Printf("Pod %s/%s does not match policy: %v", req.Namespace, req.Name, err)
		return Deny(fmt.Sprintf("pod does not match policy: %v", err))
	}

	c.logger.Printf("Pod %s/%s matches signed policy, allowing", req.Namespace, req.Name)
	return Allow("pod matches signed policy")
}

// getAnnotation extracts an annotation from pod metadata
func (c *SignatureVerificationController) getAnnotation(pod map[string]interface{}, key string) (string, bool) {
	metadata, ok := pod["metadata"].(map[string]interface{})
	if !ok {
		return "", false
	}

	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		return "", false
	}

	value, ok := annotations[key].(string)
	return value, ok
}

// checkPodAgainstPolicy verifies the pod spec matches the signed policy
func (c *SignatureVerificationController) checkPodAgainstPolicy(pod map[string]interface{}, policy *Policy) error {
	spec, ok := pod["spec"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("pod has no spec")
	}

	// Check container images
	if err := c.checkContainerImages(spec, policy.AllowedImages); err != nil {
		return err
	}

	// Check host namespaces
	if err := c.checkHostNamespaces(spec, policy); err != nil {
		return err
	}

	// Check privileged containers and capabilities
	if err := c.checkSecurityContext(spec, policy); err != nil {
		return err
	}

	// Check node selectors
	if err := c.checkNodeSelectors(spec, policy.AllowedNodeSelectors); err != nil {
		return err
	}

	return nil
}

// checkContainerImages verifies all container images match the allowed patterns
func (c *SignatureVerificationController) checkContainerImages(spec map[string]interface{}, allowedImages []string) error {
	if len(allowedImages) == 0 {
		return nil // No image restrictions
	}

	// Check containers
	if containers, ok := spec["containers"].([]interface{}); ok {
		for _, container := range containers {
			if containerMap, ok := container.(map[string]interface{}); ok {
				image, _ := containerMap["image"].(string)
				if !c.imageMatchesPatterns(image, allowedImages) {
					return fmt.Errorf("container image '%s' not allowed by policy", image)
				}
			}
		}
	}

	// Check initContainers
	if initContainers, ok := spec["initContainers"].([]interface{}); ok {
		for _, container := range initContainers {
			if containerMap, ok := container.(map[string]interface{}); ok {
				image, _ := containerMap["image"].(string)
				if !c.imageMatchesPatterns(image, allowedImages) {
					return fmt.Errorf("init container image '%s' not allowed by policy", image)
				}
			}
		}
	}

	return nil
}

// imageMatchesPatterns checks if an image matches any of the allowed patterns
func (c *SignatureVerificationController) imageMatchesPatterns(image string, patterns []string) bool {
	for _, pattern := range patterns {
		if c.matchWildcard(pattern, image) {
			return true
		}
	}
	return false
}

// matchWildcard matches a string against a pattern with * wildcards
func (c *SignatureVerificationController) matchWildcard(pattern, str string) bool {
	// Convert wildcard pattern to regex
	regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
	regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")

	matched, err := regexp.MatchString(regexPattern, str)
	if err != nil {
		return false
	}
	return matched
}

// checkHostNamespaces verifies host namespace settings match the policy
func (c *SignatureVerificationController) checkHostNamespaces(spec map[string]interface{}, policy *Policy) error {
	hostNetwork, _ := spec["hostNetwork"].(bool)
	if hostNetwork && !policy.AllowHostNetwork {
		return fmt.Errorf("hostNetwork not allowed by policy")
	}

	hostPID, _ := spec["hostPID"].(bool)
	if hostPID && !policy.AllowHostPID {
		return fmt.Errorf("hostPID not allowed by policy")
	}

	hostIPC, _ := spec["hostIPC"].(bool)
	if hostIPC && !policy.AllowHostIPC {
		return fmt.Errorf("hostIPC not allowed by policy")
	}

	return nil
}

// checkSecurityContext verifies security context settings match the policy
func (c *SignatureVerificationController) checkSecurityContext(spec map[string]interface{}, policy *Policy) error {
	// Check containers
	if containers, ok := spec["containers"].([]interface{}); ok {
		for _, container := range containers {
			if containerMap, ok := container.(map[string]interface{}); ok {
				if err := c.checkContainerSecurityContext(containerMap, policy); err != nil {
					name, _ := containerMap["name"].(string)
					return fmt.Errorf("container '%s': %v", name, err)
				}
			}
		}
	}

	// Check initContainers
	if initContainers, ok := spec["initContainers"].([]interface{}); ok {
		for _, container := range initContainers {
			if containerMap, ok := container.(map[string]interface{}); ok {
				if err := c.checkContainerSecurityContext(containerMap, policy); err != nil {
					name, _ := containerMap["name"].(string)
					return fmt.Errorf("init container '%s': %v", name, err)
				}
			}
		}
	}

	return nil
}

// checkContainerSecurityContext checks a single container's security context
func (c *SignatureVerificationController) checkContainerSecurityContext(container map[string]interface{}, policy *Policy) error {
	securityContext, ok := container["securityContext"].(map[string]interface{})
	if !ok {
		return nil // No security context
	}

	// Check privileged
	privileged, _ := securityContext["privileged"].(bool)
	if privileged && !policy.AllowPrivileged {
		return fmt.Errorf("privileged containers not allowed by policy")
	}

	// Check capabilities
	if capabilities, ok := securityContext["capabilities"].(map[string]interface{}); ok {
		if add, ok := capabilities["add"].([]interface{}); ok {
			for _, cap := range add {
				capStr, _ := cap.(string)
				if !c.isCapabilityAllowed(capStr, policy.AllowedCapabilities) {
					return fmt.Errorf("capability '%s' not allowed by policy", capStr)
				}
			}
		}
	}

	return nil
}

// isCapabilityAllowed checks if a capability is in the allowed list
func (c *SignatureVerificationController) isCapabilityAllowed(cap string, allowedCaps []string) bool {
	if len(allowedCaps) == 0 {
		return true // No restrictions
	}
	for _, allowed := range allowedCaps {
		if strings.EqualFold(allowed, cap) || allowed == "*" {
			return true
		}
	}
	return false
}

// checkNodeSelectors verifies node selectors match the policy
func (c *SignatureVerificationController) checkNodeSelectors(spec map[string]interface{}, allowedSelectors map[string]string) error {
	if len(allowedSelectors) == 0 {
		return nil // No restrictions
	}

	nodeSelector, ok := spec["nodeSelector"].(map[string]interface{})
	if !ok {
		return nil // No node selector in pod
	}

	// Check that pod's node selector matches what's allowed
	for key, value := range nodeSelector {
		valueStr, _ := value.(string)
		allowedValue, exists := allowedSelectors[key]
		if !exists {
			return fmt.Errorf("node selector key '%s' not allowed by policy", key)
		}
		if allowedValue != "*" && allowedValue != valueStr {
			return fmt.Errorf("node selector '%s=%s' not allowed by policy (allowed: %s)", key, valueStr, allowedValue)
		}
	}

	return nil
}

// verifySignature verifies the signature against the hash
func (c *SignatureVerificationController) verifySignature(hash, signature []byte) error {
	switch key := c.publicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, hash, signature)

	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, hash, signature) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported key type: %T", c.publicKey)
	}
}

// loadPublicKey loads a public key from a certificate or public key PEM file
func loadPublicKey(certPath string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		return cert.PublicKey, nil

	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		return key, nil

	case "RSA PUBLIC KEY":
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
		}
		return key, nil

	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}
}
