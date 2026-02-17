// attestation-verifier runs a REST API server that verifies attestation
// evidence produced by the attestation-server's /attest endpoint.
//
// Usage:
//
//	attestation-verifier [-addr :8901]
//
// Endpoint:
//
//	POST /verify
//
// Request body (JSON):
//
//	{
//	  "evidence": {              // the full response from /attest
//	    "tpmQuote":      "…",   // base64
//	    "hclReport":     "…",   // base64
//	    "snpReport":     "…",   // base64
//	    "aikCert":       "…",   // base64 (optional)
//	    "pcrs":          {"0":"…", …},  // index → base64 digest
//	  },
//	  "nonce":   "…",           // base64 or raw string: expected TPM quote nonce
//	  "product": "Milan"        // AMD product name (optional, default "Milan")
//	}
//
// The verifier performs 7+ independent checks that mirror the trust chain
// validated by the azure-cvm-tooling Rust crate:
//
//  1. akKeyExtraction       – HCLAkPub RSA key extracted from runtime claims
//  2. quoteFormat           – TPM quote blob parsed (TPM2B_ATTEST + TPMT_SIGNATURE)
//  3. tpmQuoteSignature     – RSA-SHA256 quote signature verified with HCLAkPub
//  4. nonce                 – extraData in quote matches expected nonce
//  5. pcrDigest             – SHA256(PCR values) matches quote digest
//  6. reportDataBinding     – SHA256(VarData) == SNP report_data[0:32]
//  7. snp*                  – AMD cert chain (ARK→ASK→VCEK) + SNP ECDSA signature
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/gaurav137/conf-node/pkg/verify"
)

// ──────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ──────────────────────────────────────────────────────────────────────────────

// VerifyRequest is the JSON body expected by the /verify endpoint.
type VerifyRequest struct {
	Evidence Evidence `json:"evidence"`          // attestation-server /attest response
	Nonce    string   `json:"nonce"`             // expected nonce (base64 or raw string)
	Product  string   `json:"product,omitempty"` // AMD product: "Milan" (default), "Genoa"
}

// Evidence mirrors the attestation-server's AttestResponse.
// RuntimeClaims are extracted automatically from the HCL report and do not need
// to be supplied by the caller.
type Evidence struct {
	TPMQuote  string            `json:"tpmQuote"`
	HCLReport string            `json:"hclReport"`
	SNPReport string            `json:"snpReport"`
	AIKCert   string            `json:"aikCert,omitempty"`
	PCRs      map[string]string `json:"pcrs"`
}

// ──────────────────────────────────────────────────────────────────────────────
// main
// ──────────────────────────────────────────────────────────────────────────────

func main() {
	addr := flag.String("addr", ":8901", "listen address (host:port)")
	flag.Parse()

	http.HandleFunc("/verify", verifyHandler)

	fmt.Printf("attestation-verifier listening on %s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

// ──────────────────────────────────────────────────────────────────────────────
// Handler
// ──────────────────────────────────────────────────────────────────────────────

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed, use POST", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON body: %v", err), http.StatusBadRequest)
		return
	}

	// ── Decode base64 fields ─────────────────────────────────────────────

	tpmQuote, err := base64.StdEncoding.DecodeString(req.Evidence.TPMQuote)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid tpmQuote base64: %v", err), http.StatusBadRequest)
		return
	}

	hclReport, err := base64.StdEncoding.DecodeString(req.Evidence.HCLReport)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid hclReport base64: %v", err), http.StatusBadRequest)
		return
	}

	snpReport, err := base64.StdEncoding.DecodeString(req.Evidence.SNPReport)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid snpReport base64: %v", err), http.StatusBadRequest)
		return
	}

	var aikCert []byte
	if req.Evidence.AIKCert != "" {
		aikCert, err = base64.StdEncoding.DecodeString(req.Evidence.AIKCert)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid aikCert base64: %v", err), http.StatusBadRequest)
			return
		}
	}

	// ── Decode PCR values ────────────────────────────────────────────────

	pcrValues := make(map[int][]byte, len(req.Evidence.PCRs))
	for k, v := range req.Evidence.PCRs {
		idx, err := strconv.Atoi(k)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid PCR index %q: %v", k, err), http.StatusBadRequest)
			return
		}
		digest, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid base64 for PCR %d: %v", idx, err), http.StatusBadRequest)
			return
		}
		pcrValues[idx] = digest
	}

	// ── Decode nonce ─────────────────────────────────────────────────────
	// Accept base64-encoded bytes or a raw string.

	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		nonce = []byte(req.Nonce)
	}

	// ── Product defaults to Milan ────────────────────────────────────────

	product := req.Product
	if product == "" {
		product = "Milan"
	}

	// ── Run verification ─────────────────────────────────────────────────

	result := verify.VerifyAll(&verify.EvidenceInput{
		TPMQuote:   tpmQuote,
		HCLReport:  hclReport,
		SNPReport:  snpReport,
		AIKCert:    aikCert,
		PCRValues:  pcrValues,
		Nonce:      nonce,
		AMDProduct: product,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
