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
	"sort"
)

const (
	// SignatureAnnotation is the annotation key for the pod spec signature
	SignatureAnnotation = "kubelet-proxy.io/signature"

	// SignatureAlgorithmAnnotation optionally specifies the signature algorithm
	// Defaults to "sha256" if not specified
	SignatureAlgorithmAnnotation = "kubelet-proxy.io/signature-algorithm"
)

// SignatureVerificationController verifies pod spec signatures
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

// Admit verifies the pod spec signature
func (c *SignatureVerificationController) Admit(req *Request) *Decision {
	// Allow all pods in kube-system namespace without signature verification
	if req.Namespace == "kube-system" {
		c.logger.Printf("Pod %s/%s allowed: kube-system namespace is exempt from signature verification", req.Namespace, req.Name)
		return Allow("kube-system namespace is exempt from signature verification")
	}

	// Get the signature from annotations
	signature, hasSignature := c.getSignatureAnnotation(req.Pod)
	if !hasSignature {
		// No signature annotation - deny by default when signature verification is enabled
		c.logger.Printf("Pod %s/%s has no signature annotation", req.Namespace, req.Name)
		return Deny("pod spec signature required but not found (missing annotation: " + SignatureAnnotation + ")")
	}

	// Extract and canonicalize the pod spec
	spec, err := c.extractPodSpec(req.Pod)
	if err != nil {
		c.logger.Printf("Failed to extract pod spec for %s/%s: %v", req.Namespace, req.Name, err)
		return Deny(fmt.Sprintf("failed to extract pod spec: %v", err))
	}

	// Compute hash of the canonical spec
	specHash, err := c.computeSpecHash(spec)
	if err != nil {
		c.logger.Printf("Failed to compute spec hash for %s/%s: %v", req.Namespace, req.Name, err)
		return Deny(fmt.Sprintf("failed to compute spec hash: %v", err))
	}

	// Decode the signature
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		c.logger.Printf("Invalid signature encoding for %s/%s: %v", req.Namespace, req.Name, err)
		return Deny("invalid signature encoding: must be base64")
	}

	// Verify the signature
	if err := c.verifySignature(specHash, signatureBytes); err != nil {
		c.logger.Printf("Signature verification failed for %s/%s: %v", req.Namespace, req.Name, err)
		return Deny(fmt.Sprintf("signature verification failed: %v", err))
	}

	c.logger.Printf("Signature verified for pod %s/%s", req.Namespace, req.Name)
	return Allow("signature verified")
}

// getSignatureAnnotation extracts the signature from pod annotations
func (c *SignatureVerificationController) getSignatureAnnotation(pod map[string]interface{}) (string, bool) {
	metadata, ok := pod["metadata"].(map[string]interface{})
	if !ok {
		return "", false
	}

	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		return "", false
	}

	signature, ok := annotations[SignatureAnnotation].(string)
	return signature, ok
}

// extractPodSpec extracts the spec from a pod object
func (c *SignatureVerificationController) extractPodSpec(pod map[string]interface{}) (map[string]interface{}, error) {
	spec, ok := pod["spec"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("pod has no spec")
	}
	return spec, nil
}

// computeSpecHash computes a SHA256 hash of the canonicalized pod spec
func (c *SignatureVerificationController) computeSpecHash(spec map[string]interface{}) ([]byte, error) {
	// Canonicalize the spec by marshaling to JSON with sorted keys
	canonicalJSON, err := canonicalizeJSON(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize spec: %w", err)
	}

	// Compute SHA256 hash
	hash := sha256.Sum256(canonicalJSON)
	return hash[:], nil
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

// canonicalizeJSON converts a map to canonical JSON (sorted keys, no extra whitespace)
func canonicalizeJSON(v interface{}) ([]byte, error) {
	// First marshal to get a clean representation
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	// Unmarshal into an ordered structure and re-marshal
	var obj interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}

	return marshalCanonical(obj)
}

// marshalCanonical marshals to JSON with sorted keys
func marshalCanonical(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		// Sort keys
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// Build canonical JSON
		result := []byte("{")
		for i, k := range keys {
			if i > 0 {
				result = append(result, ',')
			}
			keyJSON, _ := json.Marshal(k)
			result = append(result, keyJSON...)
			result = append(result, ':')
			valJSON, err := marshalCanonical(val[k])
			if err != nil {
				return nil, err
			}
			result = append(result, valJSON...)
		}
		result = append(result, '}')
		return result, nil

	case []interface{}:
		result := []byte("[")
		for i, item := range val {
			if i > 0 {
				result = append(result, ',')
			}
			itemJSON, err := marshalCanonical(item)
			if err != nil {
				return nil, err
			}
			result = append(result, itemJSON...)
		}
		result = append(result, ']')
		return result, nil

	default:
		return json.Marshal(v)
	}
}
