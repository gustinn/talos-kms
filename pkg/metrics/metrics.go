// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package metrics provides a Prometheus implementation of server.Observer.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gustinn/talos-kms/pkg/server"
)

// Recorder records KMS request metrics. It implements server.Observer.
type Recorder struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// New creates a Recorder and registers its metrics with reg.
func New(reg prometheus.Registerer) *Recorder {
	r := &Recorder{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kms_requests_total",
			Help: "Total number of KMS requests by operation and outcome.",
		}, []string{"operation", "outcome"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "kms_request_duration_seconds",
			Help:    "KMS request latency in seconds by operation.",
			Buckets: prometheus.DefBuckets,
		}, []string{"operation"}),
	}

	reg.MustRegister(r.requests, r.duration)

	return r
}

// RecordRequest implements server.Observer.
func (r *Recorder) RecordRequest(op server.Operation, outcome server.Outcome, duration time.Duration) {
	r.requests.WithLabelValues(string(op), string(outcome)).Inc()
	r.duration.WithLabelValues(string(op)).Observe(duration.Seconds())
}
