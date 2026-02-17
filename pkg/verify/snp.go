package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/gaurav137/conf-node/pkg/hcl"
)

// ──────────────────────────────────────────────────────────────────────────────
// SNP report byte offsets & sizes (AMD SEV-SNP ABI, Table 21)
// All multi-byte fields are little-endian.
// ──────────────────────────────────────────────────────────────────────────────

const (
	snpReportDataOffset  = 0x50 // report_data field (64 bytes)
	snpReportDataSize    = 64
	snpReportedTCBOffset = 0x180 // reported_tcb field (8 bytes)
	snpChipIDOffset      = 0x1A0 // chip_id field (64 bytes)
	snpChipIDSize        = 64
	snpSignatureOffset   = 0x2A0 // ECDSA signature (512 bytes)
	snpSignedRegionEnd   = 0x2A0 // bytes [0, 0x2A0) are signed
	snpSigComponentBytes = 48    // P-384 = 48 bytes per ECDSA component
	snpSigPaddedSize     = 72    // each R/S padded to 72 bytes in report

	amdKDSBaseURL = "https://kdsintf.amd.com"
)

// ──────────────────────────────────────────────────────────────────────────────
// TCB version
// ──────────────────────────────────────────────────────────────────────────────

// TCBVersion holds the SVN components from the SNP report's reported_tcb.
//
//	byte 0: Bootloader
//	byte 1: TEE
//	byte 6: SNP firmware
//	byte 7: Microcode
type TCBVersion struct {
	Bootloader uint8
	TEE        uint8
	SNP        uint8
	Microcode  uint8
}

// ParseTCBVersion extracts TCB version components from the 8-byte field.
func ParseTCBVersion(tcb []byte) TCBVersion {
	return TCBVersion{
		Bootloader: tcb[0],
		TEE:        tcb[1],
		SNP:        tcb[6],
		Microcode:  tcb[7],
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// AMD Key Distribution Service (KDS) helpers
// ──────────────────────────────────────────────────────────────────────────────

// FetchVCEK downloads the VCEK certificate (DER) from AMD's KDS.
//
//	URL: https://kdsintf.amd.com/vcek/v1/{product}/{chip_id_hex}?blSPL=…&teeSPL=…&snpSPL=…&ucodeSPL=…
func FetchVCEK(product string, chipID []byte, tcb TCBVersion) (*x509.Certificate, error) {
	chipIDHex := hex.EncodeToString(chipID)
	url := fmt.Sprintf("%s/vcek/v1/%s/%s?blSPL=%d&teeSPL=%d&snpSPL=%d&ucodeSPL=%d",
		amdKDSBaseURL, product, chipIDHex,
		tcb.Bootloader, tcb.TEE, tcb.SNP, tcb.Microcode)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET VCEK: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AMD KDS returned HTTP %d for VCEK", resp.StatusCode)
	}

	der, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read VCEK body: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse VCEK certificate: %w", err)
	}
	return cert, nil
}

// FetchCertChain downloads the ASK + ARK certificate chain (PEM) from AMD's
// KDS and returns (ASK, ARK).  The root (ARK) is identified by checking which
// certificate is self-signed.
//
//	URL: https://kdsintf.amd.com/vcek/v1/{product}/cert_chain
func FetchCertChain(product string) (ask, ark *x509.Certificate, err error) {
	url := fmt.Sprintf("%s/vcek/v1/%s/cert_chain", amdKDSBaseURL, product)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, nil, fmt.Errorf("HTTP GET cert_chain: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("AMD KDS returned HTTP %d for cert_chain", resp.StatusCode)
	}

	pemData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read cert_chain body: %w", err)
	}

	// Parse all PEM blocks.
	var certs []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse cert from chain: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) < 2 {
		return nil, nil, fmt.Errorf("expected ≥2 certs in chain, got %d", len(certs))
	}

	// Identify root (self-signed) vs intermediate.
	for _, c := range certs {
		if err := c.CheckSignatureFrom(c); err == nil {
			ark = c
		} else {
			ask = c
		}
	}
	if ark == nil || ask == nil {
		return nil, nil, fmt.Errorf("could not distinguish ASK/ARK in cert chain")
	}
	return ask, ark, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Certificate chain validation
// ──────────────────────────────────────────────────────────────────────────────

// VerifySNPCertChain validates  ARK (self-signed) → ASK → VCEK.
func VerifySNPCertChain(vcek, ask, ark *x509.Certificate) error {
	// ARK must be self-signed.
	if err := ark.CheckSignatureFrom(ark); err != nil {
		return fmt.Errorf("ARK is not self-signed: %w", err)
	}
	// ASK signed by ARK.
	if err := ask.CheckSignatureFrom(ark); err != nil {
		return fmt.Errorf("ASK not signed by ARK: %w", err)
	}
	// VCEK signed by ASK.
	if err := vcek.CheckSignatureFrom(ask); err != nil {
		return fmt.Errorf("VCEK not signed by ASK: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// SNP report signature verification
// ──────────────────────────────────────────────────────────────────────────────

// VerifySNPReportSignature checks the ECDSA-P384-SHA384 signature over the
// signed region (bytes 0–0x29F) of the SNP report using the VCEK public key.
//
// The signature components R and S are stored in little-endian format in the
// report, each padded from 48 to 72 bytes.
func VerifySNPReportSignature(snpReport []byte, vcek *x509.Certificate) error {
	if len(snpReport) < hcl.SNPReportSize {
		return fmt.Errorf("SNP report too small: %d bytes", len(snpReport))
	}

	ecKey, ok := vcek.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("VCEK public key is not ECDSA")
	}
	if ecKey.Curve != elliptic.P384() {
		return fmt.Errorf("VCEK key curve is not P-384")
	}

	// Hash the signed region.
	hash := sha512.Sum384(snpReport[:snpSignedRegionEnd])

	// Extract R (little-endian, 48 useful bytes).
	rBytes := make([]byte, snpSigComponentBytes)
	copy(rBytes, snpReport[snpSignatureOffset:snpSignatureOffset+snpSigComponentBytes])
	reverseBytes(rBytes) // LE → BE

	// Extract S.
	sBytes := make([]byte, snpSigComponentBytes)
	copy(sBytes, snpReport[snpSignatureOffset+snpSigPaddedSize:snpSignatureOffset+snpSigPaddedSize+snpSigComponentBytes])
	reverseBytes(sBytes)

	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	if !ecdsa.Verify(ecKey, hash[:], r, s) {
		return fmt.Errorf("ECDSA-P384-SHA384 signature invalid")
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// VerifySNPReport – orchestrates all SNP checks
// ──────────────────────────────────────────────────────────────────────────────

// VerifySNPReport performs the full SNP report verification:
//  1. Fetch VCEK from AMD KDS
//  2. Fetch ASK+ARK cert chain from AMD KDS
//  3. Validate ARK → ASK → VCEK chain
//  4. Verify SNP report signature with VCEK
//
// Returns a map of check name → CheckResult so individual failures are visible.
func VerifySNPReport(snpReport []byte, product string) map[string]CheckResult {
	results := make(map[string]CheckResult)

	if len(snpReport) < hcl.SNPReportSize {
		results["snpReportFormat"] = CheckResult{
			Passed: false,
			Error:  fmt.Sprintf("SNP report too small: %d bytes (need %d)", len(snpReport), hcl.SNPReportSize),
		}
		return results
	}
	results["snpReportFormat"] = CheckResult{
		Passed: true,
		Detail: fmt.Sprintf("%d bytes, signed region 0x000–0x%03X", len(snpReport), snpSignedRegionEnd-1),
	}

	// Extract chip_id and reported_tcb.
	chipID := snpReport[snpChipIDOffset : snpChipIDOffset+snpChipIDSize]
	reportedTCB := snpReport[snpReportedTCBOffset : snpReportedTCBOffset+8]
	tcb := ParseTCBVersion(reportedTCB)

	// 1. Fetch VCEK.
	vcek, err := FetchVCEK(product, chipID, tcb)
	if err != nil {
		results["vcekFetch"] = CheckResult{Passed: false, Error: err.Error()}
		return results
	}
	results["vcekFetch"] = CheckResult{
		Passed: true,
		Detail: fmt.Sprintf("VCEK fetched for %s (bl=%d tee=%d snp=%d ucode=%d)",
			product, tcb.Bootloader, tcb.TEE, tcb.SNP, tcb.Microcode),
	}

	// 2. Fetch cert chain (ASK + ARK).
	ask, ark, err := FetchCertChain(product)
	if err != nil {
		results["certChainFetch"] = CheckResult{Passed: false, Error: err.Error()}
		return results
	}
	results["certChainFetch"] = CheckResult{
		Passed: true,
		Detail: fmt.Sprintf("ASK (%s) + ARK (%s) fetched", ask.Subject.CommonName, ark.Subject.CommonName),
	}

	// 3. Validate cert chain.
	if err := VerifySNPCertChain(vcek, ask, ark); err != nil {
		results["certChainValidation"] = CheckResult{Passed: false, Error: err.Error()}
	} else {
		results["certChainValidation"] = CheckResult{Passed: true, Detail: "ARK → ASK → VCEK chain valid"}
	}

	// 4. Verify SNP report signature.
	if err := VerifySNPReportSignature(snpReport, vcek); err != nil {
		results["snpSignature"] = CheckResult{Passed: false, Error: err.Error()}
	} else {
		results["snpSignature"] = CheckResult{Passed: true, Detail: "ECDSA-P384-SHA384 signature valid"}
	}

	return results
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

// reverseBytes reverses a byte slice in-place (little-endian ↔ big-endian).
func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}
