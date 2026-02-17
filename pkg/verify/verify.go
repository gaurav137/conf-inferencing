// Package verify implements attestation evidence verification for Azure
// Confidential VMs. It validates the full trust chain:
//
//	AMD ARK → ASK → VCEK → SNP Report → report_data → VarData(HCLAkPub) → TPM Quote
//
// TPM quote structures are parsed using go-tpm/tpm2.
package verify

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"

	"github.com/gaurav137/conf-node/pkg/hcl"
	"github.com/google/go-tpm/tpm2"
)

// ──────────────────────────────────────────────────────────────────────────────
// Public types
// ──────────────────────────────────────────────────────────────────────────────

// EvidenceInput holds the decoded attestation evidence for verification.
// RuntimeClaims (including HCLAkPub) are extracted automatically from the HCL report.
type EvidenceInput struct {
	TPMQuote   []byte         // Marshalled TPM quote blob (TPM2B_ATTEST ‖ TPMT_SIGNATURE)
	HCLReport  []byte         // Full HCL report blob from vTPM NVRAM
	SNPReport  []byte         // 1184-byte AMD SNP attestation report
	AIKCert    []byte         // AIK x.509 certificate (DER), optional
	PCRValues  map[int][]byte // PCR index → SHA256 digest
	Nonce      []byte         // Expected nonce (extraData in quote)
	AMDProduct string         // AMD product name for KDS: "Milan" (default), "Genoa"
}

// VerifyResult holds the outcome of all verification checks.
type VerifyResult struct {
	Verified      bool                   `json:"verified"` // true iff every check passed
	Checks        map[string]CheckResult `json:"checks"`
	RuntimeClaims json.RawMessage        `json:"runtimeClaims,omitempty"` // parsed runtime claims from HCL report (only on success)
}

// CheckResult holds the result of a single verification check.
type CheckResult struct {
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
	Error  string `json:"error,omitempty"`
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal types
// ──────────────────────────────────────────────────────────────────────────────

// attestInfo holds fields extracted from a parsed TPMS_ATTEST structure.
type attestInfo struct {
	Nonce     []byte
	PCRDigest []byte
}

// jwk is a minimal JSON Web Key representation for RSA public keys.
type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"` // base64url
	E   string `json:"e"` // base64url
}

// runtimeClaimsKeys is used to extract the keys array from runtime claims.
type runtimeClaimsKeys struct {
	Keys []json.RawMessage `json:"keys"`
}

// ──────────────────────────────────────────────────────────────────────────────
// VerifyAll
// ──────────────────────────────────────────────────────────────────────────────

// VerifyAll runs every verification check on the provided evidence and returns
// a VerifyResult with per-check outcomes.
func VerifyAll(input *EvidenceInput) *VerifyResult {
	if input.AMDProduct == "" {
		input.AMDProduct = "Milan"
	}

	result := &VerifyResult{
		Verified: true,
		Checks:   make(map[string]CheckResult),
	}

	// ── 0. Parse runtime claims from HCL report ─────────────────────────
	claimsJSON, err := parseRuntimeClaimsFromHCL(input.HCLReport)
	if err != nil {
		result.Checks["runtimeClaimsParsing"] = CheckResult{Passed: false, Error: err.Error()}
	} else {
		result.Checks["runtimeClaimsParsing"] = CheckResult{Passed: true, Detail: "runtime claims extracted from HCL report"}
	}

	// ── 1. Extract AK public key from runtime claims ─────────────────────
	akPubKey, err := extractAKPubKey(claimsJSON)
	if err != nil {
		result.Checks["akKeyExtraction"] = CheckResult{Passed: false, Error: err.Error()}
	} else {
		result.Checks["akKeyExtraction"] = CheckResult{
			Passed: true,
			Detail: fmt.Sprintf("HCLAkPub RSA-%d extracted from runtime claims", akPubKey.N.BitLen()),
		}
	}

	// ── 2. Parse TPM quote ───────────────────────────────────────────────
	attestRaw, info, rsaSig, err := parseTPMQuote(input.TPMQuote)
	if err != nil {
		result.Checks["quoteFormat"] = CheckResult{Passed: false, Error: err.Error()}
		result.Verified = false
		return result
	}
	result.Checks["quoteFormat"] = CheckResult{Passed: true, Detail: "TPM quote parsed successfully"}

	// ── 3. Verify TPM quote signature ────────────────────────────────────
	if akPubKey != nil && attestRaw != nil {
		if err := verifyQuoteSignature(attestRaw, rsaSig, akPubKey); err != nil {
			result.Checks["tpmQuoteSignature"] = CheckResult{Passed: false, Error: err.Error()}
		} else {
			result.Checks["tpmQuoteSignature"] = CheckResult{Passed: true, Detail: "RSA-SHA256 signature valid"}
		}
	} else {
		result.Checks["tpmQuoteSignature"] = CheckResult{Passed: false, Error: "skipped: AK public key not available"}
	}

	// ── 4. Verify nonce ──────────────────────────────────────────────────
	if bytes.Equal(info.Nonce, input.Nonce) {
		result.Checks["nonce"] = CheckResult{Passed: true, Detail: "nonce matches expected value"}
	} else {
		result.Checks["nonce"] = CheckResult{
			Passed: false,
			Error:  fmt.Sprintf("nonce mismatch: got %x, expected %x", info.Nonce, input.Nonce),
		}
	}

	// ── 5. Verify PCR digest ─────────────────────────────────────────────
	if err := verifyPCRDigest(input.PCRValues, info.PCRDigest); err != nil {
		result.Checks["pcrDigest"] = CheckResult{Passed: false, Error: err.Error()}
	} else {
		result.Checks["pcrDigest"] = CheckResult{
			Passed: true,
			Detail: fmt.Sprintf("SHA256(PCR values) matches quote digest (%d PCRs)", len(input.PCRValues)),
		}
	}

	// ── 6. Verify report_data binding (VarData hash) ─────────────────────
	if err := verifyReportDataBinding(input.HCLReport, input.SNPReport); err != nil {
		result.Checks["reportDataBinding"] = CheckResult{Passed: false, Error: err.Error()}
	} else {
		result.Checks["reportDataBinding"] = CheckResult{
			Passed: true,
			Detail: "SHA256(runtime claims) == report_data[0:32]",
		}
	}

	// ── 7. Verify SNP report (AMD VCEK signature + cert chain) ───────────
	snpResults := VerifySNPReport(input.SNPReport, input.AMDProduct)
	for k, v := range snpResults {
		result.Checks[k] = v
	}

	// ── Compute overall verdict ──────────────────────────────────────────
	for _, check := range result.Checks {
		if !check.Passed {
			result.Verified = false
		}
	}

	// Include parsed runtime claims on successful verification
	if result.Verified && len(claimsJSON) > 0 {
		result.RuntimeClaims = claimsJSON
	}

	return result
}

// ──────────────────────────────────────────────────────────────────────────────
// Runtime claims parsing from HCL report
// ──────────────────────────────────────────────────────────────────────────────

// parseRuntimeClaimsFromHCL extracts the raw JSON runtime claims from the HCL
// report blob using the shared hcl package.
func parseRuntimeClaimsFromHCL(hclReport []byte) (json.RawMessage, error) {
	raw, err := hcl.ExtractRuntimeClaimsRaw(hclReport)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}

// ──────────────────────────────────────────────────────────────────────────────
// AK public key extraction
// ──────────────────────────────────────────────────────────────────────────────

// extractAKPubKey finds the HCLAkPub JWK in the runtime claims and returns the
// corresponding RSA public key.
func extractAKPubKey(claimsJSON json.RawMessage) (*rsa.PublicKey, error) {
	if len(claimsJSON) == 0 {
		return nil, fmt.Errorf("no runtime claims provided")
	}

	var claims runtimeClaimsKeys
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal runtime claims: %w", err)
	}

	for _, raw := range claims.Keys {
		var key jwk
		if err := json.Unmarshal(raw, &key); err != nil {
			continue
		}
		if key.Kid == "HCLAkPub" && key.Kty == "RSA" {
			return parseRSAPublicKey(key.N, key.E)
		}
	}

	return nil, fmt.Errorf("HCLAkPub key not found in runtime claims")
}

// parseRSAPublicKey constructs an *rsa.PublicKey from base64url-encoded n and e.
func parseRSAPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)

	var e int
	for _, b := range eBytes {
		e = (e << 8) | int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// TPM quote parsing (using go-tpm/tpm2)
// ──────────────────────────────────────────────────────────────────────────────

// parseTPMQuote splits the combined quote blob into:
//   - attestBytes: the raw TPMS_ATTEST bytes (what the TPM signed)
//   - info:        parsed nonce and PCR digest from TPMS_ATTEST
//   - rsaSig:      raw RSA signature bytes
//
// The blob layout is  [TPM2B_ATTEST] [TPMT_SIGNATURE]  where TPM2B_ATTEST is
// a 2-byte big-endian size followed by that many bytes of TPMS_ATTEST content.
func parseTPMQuote(quoteBlob []byte) (attestBytes []byte, info *attestInfo, rsaSig []byte, err error) {
	if len(quoteBlob) < 6 {
		return nil, nil, nil, fmt.Errorf("quote blob too small: %d bytes", len(quoteBlob))
	}

	// ── Split blob: [TPM2B_ATTEST] [TPMT_SIGNATURE] ─────────────────────
	attestSize := int(binary.BigEndian.Uint16(quoteBlob[0:2]))
	if 2+attestSize > len(quoteBlob) {
		return nil, nil, nil, fmt.Errorf("TPM2B_ATTEST size %d exceeds blob length", attestSize)
	}
	attestBytes = quoteBlob[2 : 2+attestSize]
	sigBytes := quoteBlob[2+attestSize:]

	// ── Parse TPMS_ATTEST using go-tpm ──────────────────────────────────
	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](attestBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshal TPMS_ATTEST: %w", err)
	}

	quoteInfo, err := attest.Attested.Quote()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("extract TPMS_QUOTE_INFO: %w", err)
	}

	info = &attestInfo{
		Nonce:     attest.ExtraData.Buffer,
		PCRDigest: quoteInfo.PCRDigest.Buffer,
	}

	// ── Parse TPMT_SIGNATURE using go-tpm ───────────────────────────────
	if len(sigBytes) == 0 {
		return nil, nil, nil, fmt.Errorf("no signature data after TPMS_ATTEST")
	}

	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](sigBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshal TPMT_SIGNATURE: %w", err)
	}

	rsaSSA, err := sig.Signature.RSASSA()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("extract RSASSA signature: %w", err)
	}

	return attestBytes, info, rsaSSA.Sig.Buffer, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Verification helpers
// ──────────────────────────────────────────────────────────────────────────────

// verifyQuoteSignature checks the RSA-PKCS1v15-SHA256 signature over the raw
// TPMS_ATTEST bytes.
func verifyQuoteSignature(attestBytes, rsaSig []byte, pubKey *rsa.PublicKey) error {
	hash := sha256.Sum256(attestBytes)
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], rsaSig)
}

// verifyPCRDigest checks that SHA256(PCR0 ‖ PCR1 ‖ … ‖ PCRn) equals the
// expected digest from the quote.  PCR values are concatenated in ascending
// index order.
func verifyPCRDigest(pcrValues map[int][]byte, expectedDigest []byte) error {
	indices := make([]int, 0, len(pcrValues))
	for idx := range pcrValues {
		indices = append(indices, idx)
	}
	sort.Ints(indices)

	hasher := sha256.New()
	for _, idx := range indices {
		hasher.Write(pcrValues[idx])
	}
	computed := hasher.Sum(nil)

	if !bytes.Equal(computed, expectedDigest) {
		return fmt.Errorf("PCR digest mismatch: computed %x, expected %x", computed, expectedDigest)
	}
	return nil
}

// verifyReportDataBinding checks that SHA256(runtime claims JSON) equals
// snpReport.report_data[0:32].  The HCL firmware hashes only the claims JSON
// (after the 20-byte runtime data header), not the entire variable data region.
func verifyReportDataBinding(hclReport, snpReport []byte) error {
	if len(snpReport) < snpReportDataOffset+snpReportDataSize {
		return fmt.Errorf("SNP report too small: %d bytes", len(snpReport))
	}

	claimsJSON, err := hcl.ExtractRuntimeClaimsRaw(hclReport)
	if err != nil {
		return err
	}

	claimsHash := sha256.Sum256(claimsJSON)
	reportData := snpReport[snpReportDataOffset : snpReportDataOffset+32]

	if !bytes.Equal(claimsHash[:], reportData) {
		return fmt.Errorf("VarData hash mismatch: SHA256(claims)=%x, report_data[0:32]=%x",
			claimsHash[:], reportData)
	}
	return nil
}
