package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SigningServer holds the server state including the key pair
type SigningServer struct {
	privateKey *ecdsa.PrivateKey
	certPEM    []byte
	mu         sync.RWMutex
	generated  bool
	// TLS certificate for HTTPS server
	tlsCertPEM []byte
	tlsKeyPEM  []byte
}

// SignRequest is the request body for the /sign endpoint
type SignRequest struct {
	Payload string `json:"payload"`
}

// SignResponse is the response body for the /sign endpoint
type SignResponse struct {
	Signature string `json:"signature"`
}

// ErrorResponse is returned on errors
type ErrorResponse struct {
	Error string `json:"error"`
}

// NewSigningServer creates a new signing server instance
func NewSigningServer() *SigningServer {
	return &SigningServer{}
}

// GenerateKeys generates a new ECDSA key pair and self-signed certificate
func (s *SigningServer) GenerateKeys() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.generated {
		return nil // Keys already generated
	}

	// Generate ECDSA private key using P-256 curve
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create a self-signed certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "signing-server",
			Organization: []string{"kubelet-proxy"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	s.privateKey = privateKey
	s.certPEM = certPEM
	s.generated = true

	log.Println("Generated new ECDSA key pair and certificate")
	return nil
}

// Sign signs the given payload and returns the base64-encoded signature
func (s *SigningServer) Sign(payload string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.generated {
		return "", fmt.Errorf("keys not generated")
	}

	// Hash the payload
	hash := sha256.Sum256([]byte(payload))

	// Sign the hash
	signature, err := ecdsa.SignASN1(rand.Reader, s.privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// GetCertPEM returns the certificate in PEM format
func (s *SigningServer) GetCertPEM() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.generated {
		return nil, fmt.Errorf("keys not generated")
	}

	return s.certPEM, nil
}

// IsGenerated returns whether keys have been generated
func (s *SigningServer) IsGenerated() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.generated
}

// GenerateTLSCert generates a self-signed TLS certificate for the HTTPS server
func (s *SigningServer) GenerateTLSCert(hosts []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate ECDSA private key for TLS
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate TLS private key: %w", err)
	}

	// Create a self-signed certificate for TLS
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "signing-server",
			Organization: []string{"kubelet-proxy"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add SANs for the provided hosts
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	// Always include localhost
	template.DNSNames = append(template.DNSNames, "localhost", "signing-server")
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	// Encode certificate to PEM
	s.tlsCertPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal TLS private key: %w", err)
	}
	s.tlsKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	log.Printf("Generated TLS certificate with SANs: %v, %v", template.DNSNames, template.IPAddresses)
	return nil
}

// GetTLSCertPEM returns the TLS certificate in PEM format
func (s *SigningServer) GetTLSCertPEM() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tlsCertPEM
}

// GetTLSConfig returns a tls.Config using the generated certificate
func (s *SigningServer) GetTLSConfig() (*tls.Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.tlsCertPEM == nil || s.tlsKeyPEM == nil {
		return nil, fmt.Errorf("TLS certificate not generated")
	}

	cert, err := tls.X509KeyPair(s.tlsCertPEM, s.tlsKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func main() {
	listenAddr := flag.String("listen-addr", ":8080", "Address to listen on")
	autoGenerate := flag.Bool("auto-generate", true, "Automatically generate signing keys on startup")
	enableTLS := flag.Bool("tls", false, "Enable HTTPS with auto-generated TLS certificate")
	tlsHosts := flag.String("tls-hosts", "", "Comma-separated list of additional hosts/IPs for TLS certificate SANs")
	flag.Parse()

	server := NewSigningServer()

	// Auto-generate signing keys on startup if enabled
	if *autoGenerate {
		if err := server.GenerateKeys(); err != nil {
			log.Fatalf("Failed to generate signing keys: %v", err)
		}
	}

	// Generate TLS certificate if TLS is enabled
	if *enableTLS {
		var hosts []string
		if *tlsHosts != "" {
			for _, h := range splitAndTrim(*tlsHosts, ",") {
				if h != "" {
					hosts = append(hosts, h)
				}
			}
		}
		if err := server.GenerateTLSCert(hosts); err != nil {
			log.Fatalf("Failed to generate TLS certificate: %v", err)
		}
	}

	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// TLS certificate endpoint (for clients to download the CA cert)
	http.HandleFunc("/tlscert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		certPEM := server.GetTLSCertPEM()
		if certPEM == nil {
			writeJSONError(w, http.StatusNotFound, "TLS not enabled")
			return
		}

		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		w.Write(certPEM)
	})

	// Generate keys endpoint
	http.HandleFunc("/generatekeys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		if server.IsGenerated() {
			writeJSON(w, http.StatusOK, map[string]string{"status": "keys already generated"})
			return
		}

		if err := server.GenerateKeys(); err != nil {
			log.Printf("Failed to generate keys: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to generate keys")
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "keys generated"})
	})

	// Sign endpoint
	http.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		if !server.IsGenerated() {
			writeJSONError(w, http.StatusPreconditionFailed, "keys not generated")
			return
		}

		// Read the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "failed to read request body")
			return
		}
		defer r.Body.Close()

		var req SignRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON request")
			return
		}

		if req.Payload == "" {
			writeJSONError(w, http.StatusBadRequest, "payload is required")
			return
		}

		signature, err := server.Sign(req.Payload)
		if err != nil {
			log.Printf("Failed to sign payload: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to sign payload")
			return
		}

		writeJSON(w, http.StatusOK, SignResponse{Signature: signature})
	})

	// Signing certificate endpoint
	http.HandleFunc("/signingcert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		if !server.IsGenerated() {
			writeJSONError(w, http.StatusPreconditionFailed, "keys not generated")
			return
		}

		certPEM, err := server.GetCertPEM()
		if err != nil {
			log.Printf("Failed to get certificate: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to get certificate")
			return
		}

		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		w.Write(certPEM)
	})

	if *enableTLS {
		tlsConfig, err := server.GetTLSConfig()
		if err != nil {
			log.Fatalf("TLS enabled but failed to get TLS config: %v", err)
		}
		httpServer := &http.Server{
			Addr:      *listenAddr,
			TLSConfig: tlsConfig,
		}
		log.Printf("Starting signing server with TLS on %s", *listenAddr)
		if err := httpServer.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	} else {
		log.Printf("Starting signing server on %s", *listenAddr)
		if err := http.ListenAndServe(*listenAddr, nil); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}
}

// splitAndTrim splits a string by separator and trims whitespace from each part
func splitAndTrim(s, sep string) []string {
	parts := make([]string, 0)
	for _, part := range strings.Split(s, sep) {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}
