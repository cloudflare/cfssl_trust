package main

import (
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/cloudflare/cfssl_trust/common"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	lastRootScan = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "last_root_scan",
			Help: "timestamp of the last time the root store was scanned",
		},
	)
	lastIntermediateScan = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "last_intermediate_scan",
			Help: "timestamp of the last time the intermediate store was scanned",
		},
	)
	expiringRoots      = newExpiringMetric("roots")
	expiringRootsCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "expiring_roots_count",
			Help: "number of root certificates expiring soon",
		},
	)
	expiringIntermediates      = newExpiringMetric("intermediates")
	expiringIntermediatesCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "expiring_intermediates_count",
			Help: "number of intermediate certificates expiring soon",
		},
	)
)

func init() {
	prometheus.MustRegister(lastRootScan)
	prometheus.MustRegister(lastIntermediateScan)
	prometheus.MustRegister(expiringRoots)
	prometheus.MustRegister(expiringRootsCount)
	prometheus.MustRegister(expiringIntermediates)
	prometheus.MustRegister(expiringIntermediatesCount)
}

var emLabels = []string{
	"subject_key_id",
	"subject",
	"not_after",
	"not_after_human",
	"delta",
}

type expiringCert struct {
	ski       string
	subject   string
	when      int64
	whenHuman string
	delta     string
}

func newExpiringCert(cert *x509.Certificate) *expiringCert {
	return &expiringCert{
		ski:       fmt.Sprintf("%x", cert.SubjectKeyId),
		subject:   common.NameToString(cert.Subject),
		when:      cert.NotAfter.Unix(),
		whenHuman: cert.NotAfter.Format(common.DateFormat),
		delta:     cert.NotAfter.Sub(time.Now()).String(),
	}
}

func (cert *expiringCert) metric(desc *prometheus.Desc) prometheus.Metric {
	values := []string{
		cert.ski,
		cert.subject,
		fmt.Sprintf("%d", cert.when),
		cert.whenHuman,
		cert.delta,
	}

	return prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(cert.when), values...)
}

type expiringMetric struct {
	store string
	certs []*expiringCert
	lock  *sync.Mutex
	desc  *prometheus.Desc
}

func newExpiringMetric(store string) *expiringMetric {
	em := &expiringMetric{
		store: store,
		lock:  &sync.Mutex{},
	}

	em.desc = prometheus.NewDesc(
		"expiring_"+em.store,
		"An expiring certificate from the "+em.store+" trust store.",
		emLabels,
		nil,
	)

	return em
}

func (em *expiringMetric) Describe(descs chan<- *prometheus.Desc) {
	em.lock.Lock()
	defer em.lock.Unlock()
	descs <- em.desc
}

func (em *expiringMetric) Set(expiring []*x509.Certificate) {
	em.lock.Lock()
	defer em.lock.Unlock()

	em.certs = []*expiringCert{}
	for _, cert := range expiring {
		em.certs = append(em.certs, newExpiringCert(cert))
	}
}

func (em *expiringMetric) Collect(metrics chan<- prometheus.Metric) {
	em.lock.Lock()
	defer em.lock.Unlock()

	for _, cert := range em.certs {
		metrics <- cert.metric(em.desc)
	}
}
