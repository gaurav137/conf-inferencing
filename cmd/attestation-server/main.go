package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/gaurav137/conf-node/pkg/attestation"
)

// defaultNonce is used as the TPM quote nonce when no nonce is provided.
const defaultNonce = "attestation-nonce-default"

// AttestRequest is the JSON body expected by the /attest endpoint.
type AttestRequest struct {
	ReportData   string `json:"reportData"`             // base64-encoded 64-byte report_data for SNP report
	Nonce        string `json:"nonce,omitempty"`        // optional base64-encoded nonce for TPM quote (max 32 bytes); defaults to fixed string
	PCRSelection []int  `json:"pcrSelection,omitempty"` // optional list of PCR indices (0-23); defaults to all 24
}

// AttestResponse is the JSON response returned by the /attest endpoint.
type AttestResponse struct {
	TPMQuote      string                     `json:"tpmQuote"`                // base64-encoded TPM quote (quoted + signature)
	HCLReport     string                     `json:"hclReport"`               // base64-encoded HCL report blob
	SNPReport     string                     `json:"snpReport"`               // base64-encoded AMD SNP attestation report
	AIKCert       string                     `json:"aikCert"`                 // base64-encoded AIK x.509 certificate (DER)
	PCRs          map[string]string          `json:"pcrs"`                    // SHA256 PCR values (index -> base64-encoded digest)
	RuntimeClaims *attestation.RuntimeClaims `json:"runtimeClaims,omitempty"` // parsed runtime claims from HCL report
}

func main() {
	addr := flag.String("addr", ":8900", "listen address (host:port)")
	flag.Parse()

	http.HandleFunc("/attest", attestHandler)

	fmt.Printf("attestation-server listening on %s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func attestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed, use POST", http.StatusMethodNotAllowed)
		return
	}

	var req AttestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON body: %v", err), http.StatusBadRequest)
		return
	}

	if req.ReportData == "" {
		http.Error(w, "reportData is required", http.StatusBadRequest)
		return
	}

	rdBytes, err := base64.StdEncoding.DecodeString(req.ReportData)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid base64 reportData: %v", err), http.StatusBadRequest)
		return
	}
	if len(rdBytes) != attestation.ReportDataSize {
		http.Error(w, fmt.Sprintf("reportData must be exactly %d bytes, got %d",
			attestation.ReportDataSize, len(rdBytes)), http.StatusBadRequest)
		return
	}

	// Determine the TPM quote nonce.
	// If the caller provided a nonce, decode and use it (max 32 bytes).
	// Otherwise fall back to the fixed default string.
	var nonce []byte
	if req.Nonce != "" {
		nonce, err = base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid base64 nonce: %v", err), http.StatusBadRequest)
			return
		}
		if len(nonce) > 32 {
			http.Error(w, fmt.Sprintf("nonce must be at most 32 bytes, got %d", len(nonce)), http.StatusBadRequest)
			return
		}
	} else {
		nonce = []byte(defaultNonce)
	}
	// Validate PCR selection if provided
	for _, pcr := range req.PCRSelection {
		if pcr < 0 || pcr > 23 {
			http.Error(w, fmt.Sprintf("pcrSelection values must be 0-23, got %d", pcr), http.StatusBadRequest)
			return
		}
	}

	evidence, err := attestation.CollectEvidenceWithReportData(nonce, rdBytes, req.PCRSelection)
	if err != nil {
		log.Printf("attestation failed: %v", err)
		http.Error(w, fmt.Sprintf("attestation failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Encode PCR values as string-keyed map for JSON
	pcrMap := make(map[string]string, len(evidence.PCRs))
	for idx, digest := range evidence.PCRs {
		pcrMap[fmt.Sprintf("%d", idx)] = base64.StdEncoding.EncodeToString(digest)
	}

	resp := AttestResponse{
		TPMQuote:      base64.StdEncoding.EncodeToString(evidence.TPMQuote),
		HCLReport:     base64.StdEncoding.EncodeToString(evidence.HCLReport),
		SNPReport:     base64.StdEncoding.EncodeToString(evidence.SNPReport),
		PCRs:          pcrMap,
		RuntimeClaims: evidence.RuntimeClaims,
	}
	if evidence.AIKCert != nil {
		resp.AIKCert = base64.StdEncoding.EncodeToString(evidence.AIKCert)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
