package main

import (
	"bufio"
	"bytes"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Execute a iptables command in the mangle table and fataly exit the application
// if it fails
func iptablesExecute(args ...string) {
	// iptables must be ran in the mangle table
	trueArguments := make([]string, 2, len(args)+2)
	trueArguments[0] = "-t"
	trueArguments[1] = "mangle"
	trueArguments = append(trueArguments, args...)
	err := exec.Command("iptables", trueArguments...).Run()
	// Check errors
	if err != nil {
		log.Printf("Cannot execute iptables command: %s: %T", strings.Join(trueArguments, " "), err)
		os.Exit(1)
	}
}

// Setup the rules which monitor the traffic of each client.
// Will exit the program if any of the commands fail.
// The arugment is a list of IP addresses which will be monitored.
func iptablesSetup(ips []string) {
	// Check if chains exist
	if exec.Command("iptables", "-t", "mangle", "-n", "--list", "POST_COUNTER").Run() != nil {
		// Chains do not exist, create them
		iptablesExecute("-N", "PRE_COUNTER")
		iptablesExecute("-N", "POST_COUNTER")
		iptablesExecute("-I", "PREROUTING", "-j", "PRE_COUNTER")
		iptablesExecute("-I", "POSTROUTING", "-j", "POST_COUNTER")
	} else {
		// Chains exist, just flush them
		iptablesExecute("-F", "POST_COUNTER")
		iptablesExecute("-F", "PRE_COUNTER")
	}
	// Create the new rules in each chain
	for _, ip := range ips {
		iptablesExecute("-A", "PRE_COUNTER", "-s", ip, "-j", "RETURN")
		iptablesExecute("-A", "POST_COUNTER", "-d", ip, "-j", "RETURN")
	}
	// Add last return rules in order to match every unknown traffic
	iptablesExecute("-A", "PRE_COUNTER", "-j", "RETURN")
	iptablesExecute("-A", "POST_COUNTER", "-j", "RETURN")
}

// Export the iptable metrics to a map of ip to metric
func (m *metrics) iptablesExport() {
	// Run to get info about download
	output, err := exec.Command("iptables", "-t", "mangle", "-L", "POST_COUNTER", "-n", "-v", "-x").Output()
	if err != nil {
		log.Println("cannot get download metrics:", err)
		return
	}
	// Parse download info
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Scan() // skip the headers
	scanner.Scan()
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		ip := parts[len(parts)-1] // dest IP
		previousDownload := m.previousDownload[ip]
		tx, err := strconv.ParseFloat(parts[1], 64)
		if err == nil {
			m.download.WithLabelValues(ip).Add(tx - previousDownload)
			m.previousDownload[ip] = tx
		}
	}
	// Get upload statics
	output, err = exec.Command("iptables", "-t", "mangle", "-L", "PRE_COUNTER", "-n", "-v", "-x").Output()
	if err != nil {
		log.Println("cannot get upload metrics:", err)
		return
	}
	// Parse upload info
	scanner = bufio.NewScanner(bytes.NewReader(output))
	scanner.Scan() // skip the headers
	scanner.Scan()
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		ip := parts[len(parts)-2] // source IP
		previousUpload := m.previousUpload[ip]
		tx, err := strconv.ParseFloat(parts[1], 64)
		if err == nil {
			m.upload.WithLabelValues(ip).Add(tx - previousUpload)
			m.previousUpload[ip] = tx
		}
	}
}
