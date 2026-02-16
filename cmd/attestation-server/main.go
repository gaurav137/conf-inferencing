package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/gaurav137/conf-node/pkg/attestation"
)

// AttestRequest is the JSON body expected by the /attest endpoint.
type AttestRequest struct {
	ReportData string `json:"reportData"` // base64-encoded 64-byte report_data for SNP report
}

// AttestResponse is the JSON response returned by the /attest endpoint.
type AttestResponse struct {
	TPMQuote      string                     `json:"tpmQuote"`                // base64-encoded TPM quote (quoted + signature)
	HCLReport     string                     `json:"hclReport"`               // base64-encoded HCL report blob
	SNPReport     string                     `json:"snpReport"`               // base64-encoded AMD SNP attestation report
	AIKCert       string                     `json:"aikCert"`                 // base64-encoded AIK x.509 certificate (DER)
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

	// TPM2 QualifyingData (TPM2B_DATA) is limited to 32 bytes.
	// Use SHA256(reportData) as the TPM quote nonce.
	nonceHash := sha256.Sum256(rdBytes)
	nonce := nonceHash[:]
	evidence, err := attestation.CollectEvidenceWithReportData(nonce, rdBytes)
	if err != nil {
		log.Printf("attestation failed: %v", err)
		http.Error(w, fmt.Sprintf("attestation failed: %v", err), http.StatusInternalServerError)
		return
	}

	resp := AttestResponse{
		TPMQuote:      base64.StdEncoding.EncodeToString(evidence.TPMQuote),
		HCLReport:     base64.StdEncoding.EncodeToString(evidence.HCLReport),
		SNPReport:     base64.StdEncoding.EncodeToString(evidence.SNPReport),
		RuntimeClaims: evidence.RuntimeClaims,
	}
	if evidence.AIKCert != nil {
		resp.AIKCert = base64.StdEncoding.EncodeToString(evidence.AIKCert)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
