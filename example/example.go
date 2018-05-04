package main

import (
	"github.com/kadaan/go-gin-prometheus"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

func main() {
	r := gin.New()

	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: "Gin",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests made.",
		},
		[]string{"code", "method", "url"},
	)

	duration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: "Gin",
			Name:      "request_duration_seconds",
			Help:      "The HTTP request latencies in seconds.",
			Buckets:   prometheus.ExponentialBuckets(0.5, 2, 6),
		},
		[]string{"code", "method", "url"},
	)

	requestSize := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: "Gin",
			Name:        "request_size_bytes",
			Help:        "The HTTP request sizes in bytes.",
			Buckets:   prometheus.ExponentialBuckets(128, 2, 4),
		},
		[]string{"code", "method", "url"},
	)

	responseSize := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: "Gin",
			Name:      "response_size_bytes",
			Help:      "The HTTP response sizes in bytes.",
			Buckets:   prometheus.ExponentialBuckets(512, 4, 4),
		},
		[]string{"code", "method", "url"},
	)

	ginprometheus.NewBuilder().Counter(counter).Duration(duration).RequestSize(requestSize).ResponseSize(responseSize).Use(r)

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, "Hello world!")
	})

	r.Run(":29090")
}
