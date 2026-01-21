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

// ContainerPolicy defines the policy for a single container
type ContainerPolicy struct {
	// Image is the allowed container image (supports wildcards)
	Image string `json:"image,omitempty"`

	// Privileged indicates whether the container can run as privileged
	Privileged bool `json:"privileged,omitempty"`

	// Capabilities lists allowed Linux capabilities to add
	Capabilities []string `json:"capabilities,omitempty"`
}

// Policy defines what a pod is allowed to do
// This is extracted from the pod spec at signing time and verified at admission time
type Policy struct {
	// Containers maps container name to its policy
	Containers map[string]ContainerPolicy `json:"containers,omitempty"`

	// InitContainers maps init container name to its policy
	InitContainers map[string]ContainerPolicy `json:"initContainers,omitempty"`

	// AllowHostNetwork indicates whether hostNetwork is allowed
	AllowHostNetwork bool `json:"allowHostNetwork,omitempty"`

	// AllowHostPID indicates whether hostPID is allowed
	AllowHostPID bool `json:"allowHostPID,omitempty"`

	// AllowHostIPC indicates whether hostIPC is allowed
	AllowHostIPC bool `json:"allowHostIPC,omitempty"`

	// NodeSelector lists allowed node selector key-value pairs
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
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

	// Check containers against policy
	if err := c.checkContainers(spec, "containers", policy.Containers); err != nil {
		return err
	}

	// Check init containers against policy
	if err := c.checkContainers(spec, "initContainers", policy.InitContainers); err != nil {
		return err
	}

	// Check host namespaces
	if err := c.checkHostNamespaces(spec, policy); err != nil {
		return err
	}

	// Check node selectors
	if err := c.checkNodeSelectors(spec, policy.NodeSelector); err != nil {
		return err
	}

	return nil
}

// checkContainers verifies all containers match their policies by name
func (c *SignatureVerificationController) checkContainers(spec map[string]interface{}, containerType string, containerPolicies map[string]ContainerPolicy) error {
	containers, ok := spec[containerType].([]interface{})
	if !ok {
		// No containers of this type in spec
		if len(containerPolicies) > 0 {
			return fmt.Errorf("policy specifies %s but pod has none", containerType)
		}
		return nil
	}

	// Build a set of container names from the policy
	policyNames := make(map[string]bool)
	for name := range containerPolicies {
		policyNames[name] = true
	}

	// Check each container in the spec against its policy
	for _, container := range containers {
		containerMap, ok := container.(map[string]interface{})
		if !ok {
			continue
		}

		name, _ := containerMap["name"].(string)
		if name == "" {
			return fmt.Errorf("%s has container without name", containerType)
		}

		containerPolicy, exists := containerPolicies[name]
		if !exists {
			return fmt.Errorf("%s '%s' not found in policy", containerType, name)
		}

		// Check image
		image, _ := containerMap["image"].(string)
		if !c.matchWildcard(containerPolicy.Image, image) {
			return fmt.Errorf("%s '%s': image '%s' does not match policy image '%s'", containerType, name, image, containerPolicy.Image)
		}

		// Check security context
		if err := c.checkContainerSecurityContextAgainstPolicy(containerMap, name, containerType, &containerPolicy); err != nil {
			return err
		}

		// Mark this container as found
		delete(policyNames, name)
	}

	// Check for containers in policy but not in spec
	if len(policyNames) > 0 {
		var missing []string
		for name := range policyNames {
			missing = append(missing, name)
		}
		return fmt.Errorf("policy specifies %s not found in pod: %v", containerType, missing)
	}

	return nil
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

// checkContainerSecurityContextAgainstPolicy checks a container's security context against its policy
func (c *SignatureVerificationController) checkContainerSecurityContextAgainstPolicy(container map[string]interface{}, name, containerType string, policy *ContainerPolicy) error {
	securityContext, _ := container["securityContext"].(map[string]interface{})

	// Check privileged
	privileged := false
	if securityContext != nil {
		privileged, _ = securityContext["privileged"].(bool)
	}
	if privileged != policy.Privileged {
		return fmt.Errorf("%s '%s': privileged=%v does not match policy privileged=%v", containerType, name, privileged, policy.Privileged)
	}

	// Check capabilities
	var podCaps []string
	if securityContext != nil {
		if capabilities, ok := securityContext["capabilities"].(map[string]interface{}); ok {
			if add, ok := capabilities["add"].([]interface{}); ok {
				for _, cap := range add {
					if capStr, ok := cap.(string); ok {
						podCaps = append(podCaps, capStr)
					}
				}
			}
		}
	}

	// Capabilities must match exactly (same set)
	if !c.capabilitySetsEqual(podCaps, policy.Capabilities) {
		return fmt.Errorf("%s '%s': capabilities %v do not match policy capabilities %v", containerType, name, podCaps, policy.Capabilities)
	}

	return nil
}

// capabilitySetsEqual checks if two capability slices contain the same elements
func (c *SignatureVerificationController) capabilitySetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	// Create maps for comparison (case-insensitive)
	aMap := make(map[string]bool)
	for _, cap := range a {
		aMap[strings.ToUpper(cap)] = true
	}

	for _, cap := range b {
		if !aMap[strings.ToUpper(cap)] {
			return false
		}
	}

	return true
}

// checkNodeSelectors verifies node selectors match the policy exactly
func (c *SignatureVerificationController) checkNodeSelectors(spec map[string]interface{}, policySelectors map[string]string) error {
	podSelectors, _ := spec["nodeSelector"].(map[string]interface{})

	// Convert pod selectors to map[string]string
	podSelectorMap := make(map[string]string)
	for key, value := range podSelectors {
		if valueStr, ok := value.(string); ok {
			podSelectorMap[key] = valueStr
		}
	}

	// Check that pod and policy have the same node selectors
	if len(podSelectorMap) != len(policySelectors) {
		return fmt.Errorf("node selectors count mismatch: pod has %d, policy has %d", len(podSelectorMap), len(policySelectors))
	}

	for key, policyValue := range policySelectors {
		podValue, exists := podSelectorMap[key]
		if !exists {
			return fmt.Errorf("node selector '%s' in policy but not in pod", key)
		}
		if podValue != policyValue {
			return fmt.Errorf("node selector '%s': pod has '%s', policy has '%s'", key, podValue, policyValue)
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
