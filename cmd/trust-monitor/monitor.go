// trust-monitor watches bundles and alerts when there's an issue.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/getsentry/raven-go"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	prometheusHost = os.Getenv("HOST")
	prometheusPort = os.Getenv("PORT")
	interval       = 24 * time.Hour
	window         = 30 * 24 * time.Hour
	runBookURL     = ""
	sentryDSN      = ""
	trustBaseURL   = "https://raw.githubusercontent.com/cloudflare/cfssl_trust/master/"
)

var indexHTML string

func buildIndex() {
	runbook := ""
	if runBookURL != "" {
		runbook = fmt.Sprintf(`<p>The runbook for this service can be found <a href="%s">here</a>.`, runBookURL)
	}

	sentry := ""
	if sentryDSN != "" {
		sentry = `<p>Errors will be sent to sentry.</p>`
	}

	indexHTML = fmt.Sprintf(`<!doctype html>
<html>
<head><title>Certificate Manager</title></head>
<body>
  <h1>Trust Monitor</h1>
  <p>This is a service that monitors trust bundles. It is configured to fetch the stores from
     '%s' every %s, and to alert on certificates expiring within %s.</p>
  <p>The Prometheus endpoint is at <a href="/prometheus">/prometheus</a>.</p>
  %s
  %s
</body>
</html>
`, trustBaseURL, interval, window, runbook, sentry)
}

func index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(indexHTML))
}

func monitor() {
	go scanTrustStores()
	checkAt := time.Now().Add(interval)
	for {
		time.Sleep(time.Second)
		if time.Now().After(checkAt) {
			go scanTrustStores()
			checkAt = time.Now().Add(interval)
		}
	}
}

var sentryTags = map[string]string{}

func initSentry() {
	if sentryDSN == "" {
		return
	}

	raven.SetDSN(sentryDSN)
	sentryTags["prometheus_host"] = prometheusHost
	sentryTags["prometheus_port"] = prometheusPort
	sentryTags["interval"] = interval.String()
	sentryTags["window"] = window.String()
}

func errorf(err error) {
	if sentryDSN != "" {
		raven.CaptureError(err, sentryTags)
	}

	log.Print(err)
}

func init() {
	flag.Usage = func() {
		usage(os.Stderr)
	}
}

func main() {
	var help bool

	flag.StringVar(&prometheusHost, "a", prometheusHost, "`host` to set up Prometheus endpoint on")
	flag.BoolVar(&help, "h", false, "print a help message")
	flag.DurationVar(&interval, "i", interval, "`interval` to scan trust stores")
	flag.StringVar(&prometheusPort, "p", prometheusPort, "`port` to set up Prometheus endpoint on")
	flag.StringVar(&runBookURL, "r", runBookURL, "optional `URL` for service runbook")
	flag.StringVar(&sentryDSN, "s", "", "optional `Sentry DSN`")
	flag.StringVar(&trustBaseURL, "u", trustBaseURL, "base `url` to fetch trust stores")
	flag.DurationVar(&window, "w", window, "`window` before expiration to warn on")
	flag.Parse()

	if help {
		usage(os.Stdout)
		os.Exit(0)
	}

	buildIndex()
	address := net.JoinHostPort(prometheusHost, prometheusPort)

	if sentryDSN != "" {
		go raven.CapturePanic(monitor, sentryTags)
	} else {
		go monitor()
	}

	log.Printf("starting HTTP server on %s", address)

	http.HandleFunc("/", index)
	http.Handle("/prometheus", prometheus.Handler())
	log.Fatal(http.ListenAndServe(address, nil))
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `
trust-monitor is a tool for scanning and providing metrics on expiring certificates.

trust-monitor [-a address] [-h] [-i interval] [-p port] [-r url] [-s dsn]
	      [-u url] [-w window]

Flags:

	-a address	The address to set up the HTTP endpoint on. This
			defaults to the value of the HOST environment variable
			(currently %s).
	-h		Print this help message.
	-i interval	A Go time.Duration value that is used to specify the
			interval between trust store scans. This defaults to
			24h (currently %s).
	-p port		The port to set up the HTTP endpoint on. This defaults
			to the value of the PORT environment variable
			(currently %s).
	-r url		An optional URL specifying the URL to the service
			runbook. If provided, this is listed on the index page.
	-s dsn		An optional Sentry DSN. If provided, this will be used
			to report errors and panics.
	-u url		The base URL to the trust stores; the trust store name
			will be appended to this. This defaults to the
			cfssl_trust repo (currently %s).
	-w window	The window within which expiring certificates should be
			reported. This defaults to 720h, which is 30 days
			(currently %s).
`,
		prometheusHost, interval, prometheusPort, trustBaseURL, window)
}
