package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metrics struct {
	download *prometheus.CounterVec
	upload   *prometheus.CounterVec

	previousDownload map[string]float64
	previousUpload   map[string]float64
}

func NewMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		download: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "iptables_download",
			Help: "Download done by each client",
		}, []string{"ip"}),
		upload: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "iptables_upload",
			Help: "Upload done by each client",
		}, []string{"ip"}),

		previousDownload: make(map[string]float64),
		previousUpload:   make(map[string]float64),
	}
	reg.MustRegister(m.download)
	reg.MustRegister(m.upload)
	return m
}

func main() {
	// Command line arguments
	addr := flag.String("listen-address", ":8080", "The address to listen on for HTTP requests.")
	updateInterval := flag.Int("update-interval", 15, "Update interval in seconds.")
	ipAddressesArgument := flag.String("ips", "", "List of ip addresses to monitor, comma seperated")
	flag.Parse()

	// Parse the IP addresess
	ipAddresses := strings.Split(*ipAddressesArgument, ",")
	if len(ipAddresses) == 0 || *ipAddressesArgument == "" {
		log.Printf("You must at least specify one IP address")
		return
	}
	for _, ip := range ipAddresses {
		if net.ParseIP(ip) == nil {
			log.Panicf("IP %s is not valid\n", ip)
			return
		}
	}

	// Setup the iptables
	iptablesSetup(ipAddresses)

	// Create a registery for prometheus
	reg := prometheus.NewRegistry()

	// Create new metrics and register them using the custom registry.
	m := NewMetrics(reg)
	// Regularly update the values
	go func() {
		for {
			m.iptablesExport()
			time.Sleep(time.Second * time.Duration(*updateInterval))
		}
	}()

	// Expose metrics and custom registry via an HTTP server
	// using the HandleFor function. "/metrics" is the usual endpoint for that.
	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	log.Fatal(http.ListenAndServe(*addr, nil))
}
