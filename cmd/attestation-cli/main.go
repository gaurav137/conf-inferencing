package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/gaurav137/conf-node/pkg/attestation"
)

func main() {
	reportDataFile := flag.String("report-data", "", "path to a 64-byte file to use as report_data (triggers fresh SNP report)")
	flag.Parse()

	nonce := []byte("external-verifier-nonce")

	var evidence *attestation.Evidence
	var err error

	if *reportDataFile != "" {
		// Read report_data from file
		reportData, readErr := os.ReadFile(*reportDataFile)
		if readErr != nil {
			log.Fatalf("Failed to read report-data file: %v", readErr)
		}
		if len(reportData) != attestation.ReportDataSize {
			log.Fatalf("report-data file must be exactly %d bytes, got %d", attestation.ReportDataSize, len(reportData))
		}
		log.Printf("Using report_data from %s", *reportDataFile)
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
