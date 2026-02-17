package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/gaurav137/conf-node/pkg/attestation"
)

func main() {
	reportDataFile := flag.String("report-data", "", "path to a 64-byte file to use as report_data (triggers fresh SNP report)")
	pcrsFlag := flag.String("pcrs", "", "comma-separated list of PCR indices to include (0-23); defaults to all 24")
	flag.Parse()

	nonce := []byte("external-verifier-nonce")

	// Parse PCR selection
	var pcrSlots []int
	if *pcrsFlag != "" {
		for _, s := range strings.Split(*pcrsFlag, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			v, err := strconv.Atoi(s)
			if err != nil || v < 0 || v > 23 {
				log.Fatalf("Invalid PCR index %q (must be 0-23)", s)
			}
			pcrSlots = append(pcrSlots, v)
		}
	}

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
		evidence, err = attestation.CollectEvidenceWithReportData(nonce, reportData, pcrSlots)
	} else {
		evidence, err = attestation.CollectEvidence(nonce, pcrSlots)
	}
	if err != nil {
		log.Fatalf("Attestation failed: %v", err)
	}

	fmt.Printf("SHA256(Quote): %x\n", evidence.QuoteHash)

	// Save artifacts
	os.WriteFile("tpm_quote.bin", evidence.TPMQuote, 0644)
	os.WriteFile("hcl_report.bin", evidence.HCLReport, 0644)
	os.WriteFile("snp_report.bin", evidence.SNPReport, 0644)
	os.WriteFile("aik_cert.der", evidence.AIKCert, 0644)
	fmt.Println("Saved tpm_quote.bin, hcl_report.bin, snp_report.bin, and aik_cert.der")

	// Save PCR values as JSON
	pcrOut := make(map[string]string, len(evidence.PCRs))
	for idx, digest := range evidence.PCRs {
		pcrOut[fmt.Sprintf("%d", idx)] = fmt.Sprintf("%x", digest)
	}
	pcrJSON, err := json.MarshalIndent(pcrOut, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal PCR values: %v", err)
	}
	os.WriteFile("pcr_values.json", pcrJSON, 0644)
	fmt.Println("Saved pcr_values.json")

	// Save runtime claims as JSON
	claimsJSON, err := json.MarshalIndent(evidence.RuntimeClaims, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal runtime claims: %v", err)
	}
	os.WriteFile("runtime_claims.json", claimsJSON, 0644)
	fmt.Println("Saved runtime_claims.json")
}
