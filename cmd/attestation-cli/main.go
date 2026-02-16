package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/gaurav137/conf-node/pkg/attestation"
)

func main() {
	fresh := flag.Bool("fresh", false, "write custom report_data to 0x01400002 to trigger fresh SNP report")
	flag.Parse()

	nonce := []byte("external-verifier-nonce")

	var evidence *attestation.Evidence
	var err error

	if *fresh {
		// Use SHA256(nonce) as report_data, zero-padded to 64 bytes
		reportData := make([]byte, attestation.ReportDataSize)
		h := sha256.Sum256(nonce)
		copy(reportData, h[:])
		log.Println("Requesting fresh SNP report with custom report_data...")
		evidence, err = attestation.CollectEvidenceWithReportData(nonce, reportData)
	} else {
		evidence, err = attestation.CollectEvidence(nonce)
	}
	if err != nil {
		log.Fatalf("Attestation failed: %v", err)
	}

	fmt.Printf("SHA256(Quote): %x\n", evidence.QuoteHash)

	// Save artifacts
	os.WriteFile("tpm_quote.bin", evidence.TPMQuote, 0644)
	os.WriteFile("hcl_report.bin", evidence.HCLReport, 0644)
	os.WriteFile("snp_report.bin", evidence.SNPReport, 0644)
	if evidence.AIKCert != nil {
		os.WriteFile("aik_cert.der", evidence.AIKCert, 0644)
		fmt.Println("Saved tpm_quote.bin, hcl_report.bin, snp_report.bin, and aik_cert.der")
	} else {
		fmt.Println("Saved tpm_quote.bin, hcl_report.bin, and snp_report.bin")
	}

	// Save runtime claims as JSON
	if evidence.RuntimeClaims != nil {
		claimsJSON, err := json.MarshalIndent(evidence.RuntimeClaims, "", "  ")
		if err != nil {
			log.Printf("Warning: could not marshal runtime claims: %v", err)
		} else {
			os.WriteFile("runtime_claims.json", claimsJSON, 0644)
			fmt.Println("Saved runtime_claims.json")
		}
	}
}
