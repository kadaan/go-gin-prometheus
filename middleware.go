package ginprometheus

import (
	"bytes"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"strings"

	dto "github.com/prometheus/client_model/go"
)

const magicString = "zZgWfBxLqvG8kc8IMv3POi2Bb0tZI3vAnBx+gBaFi9FyPzB/CzKUer1yufDa"

var (
	defaultMetricPath = "/metrics"
)

/*
URLLabelMappingFn is a function which can be supplied to the middleware to control
the cardinality of the request counter's "url" label, which might be required in some contexts.
For instance, if for a "/customer/:name" route you don't want to generate a time series for every
possible customer name, you could use this function:

func(c *gin.Context) string {
	url := c.Request.URL.String()
	for _, p := range c.Params {
		if p.Key == "name" {
			url = strings.Replace(url, p.Value, ":name", 1)
			break
		}
	}
	return url
}

which would map "/customer/alice" and "/customer/bob" to their template "/customer/:name".
*/
type URLLabelMappingFn func(c *gin.Context) string

func NewBuilder() *Prometheus {
	p := &Prometheus{
		MetricsPath: defaultMetricPath,
		urlLabelMappingFn: func(c *gin.Context) string {
			return c.Request.URL.String() // i.e. by default do nothing, i.e. return URL as is
		},
	}
	return p
}

type PrometheusMiddlerwareBuilder interface {
	Auth(accounts gin.Accounts) PrometheusMiddlerwareBuilder
	UrlMapping(function URLLabelMappingFn) PrometheusMiddlerwareBuilder
	Counter(counter *prometheus.CounterVec) PrometheusMiddlerwareBuilder
	Duration(observer prometheus.ObserverVec) PrometheusMiddlerwareBuilder
	RequestSize(observer prometheus.ObserverVec) PrometheusMiddlerwareBuilder
	ResponseSize(observer prometheus.ObserverVec) PrometheusMiddlerwareBuilder
	PushGateway(pushGatewayURL, metricsURL string, pushIntervalSeconds time.Duration) PrometheusPushGatewayMiddlewareBuilder
	Use(e *gin.Engine)
}

func (p *Prometheus) Auth(accounts gin.Accounts) PrometheusMiddlerwareBuilder {
	p.accounts = accounts
	return p
}

func (p *Prometheus) UrlMapping(function URLLabelMappingFn) PrometheusMiddlerwareBuilder {
	p.urlLabelMappingFn = function
	return p
}

type metricInfo struct {
	code, method, url                   string
	duration, requestSize, responseSize float64
}

type metricFunc func(metricInfo *metricInfo)

func (p *Prometheus) Counter(counter *prometheus.CounterVec) PrometheusMiddlerwareBuilder {
	code, method, url := checkLabels(counter)

	p.reqCnt = metricFunc(func(i *metricInfo) {
		counter.With(labels(code, method, url, i.code, i.method, i.url)).Inc()
	})

	return p
}

func (p *Prometheus) Duration(observer prometheus.ObserverVec) PrometheusMiddlerwareBuilder {
	code, method, url := checkLabels(observer)

	p.reqDur = metricFunc(func(i *metricInfo) {
		observer.With(labels(code, method, url, i.code, i.method, i.url)).Observe(i.duration)
	})

	return p
}

func (p *Prometheus) RequestSize(observer prometheus.ObserverVec) PrometheusMiddlerwareBuilder {
	code, method, url := checkLabels(observer)

	p.reqSz = metricFunc(func(i *metricInfo) {
		observer.With(labels(code, method, url, i.code, i.method, i.url)).Observe(i.requestSize)
	})

	return p
}

func (p *Prometheus) ResponseSize(observer prometheus.ObserverVec) PrometheusMiddlerwareBuilder {
	code, method, url := checkLabels(observer)

	p.resSz = metricFunc(func(i *metricInfo) {
		observer.With(labels(code, method, url, i.code, i.method, i.url)).Observe(i.responseSize)
	})

	return p
}

// PushGateway sends metrics to a remote pushgateway exposed on pushGatewayURL
// every pushIntervalSeconds. Metrics are fetched from metricsURL
func (p *Prometheus) PushGateway(pushGatewayURL, metricsURL string, pushIntervalSeconds time.Duration) PrometheusPushGatewayMiddlewareBuilder {
	p.ppg.pushGatewayURL = pushGatewayURL
	p.ppg.metricsURL = metricsURL
	p.ppg.pushIntervalSeconds = pushIntervalSeconds
	p.startPushTicker()
	return p
}

// Use adds the middleware to a gin engine.
func (p *Prometheus) Use(e *gin.Engine) {
	e.Use(p.handlerFunc())
	if p.accounts != nil {
		p.setMetricsPathWithAuth(e, p.accounts)
	} else {
		p.setMetricsPath(e)
	}
}

type PrometheusPushGatewayMiddlewareBuilder interface {
	Job(job string)
	ListenAddress(address string)
	Use(e *gin.Engine)
}

// Job job name, defaults to "gin"
func (p *Prometheus) Job(j string) {
	p.ppg.job = j
}

// ListenAddress for exposing metrics on address. If not set, it will be exposed at the
// same address of the gin engine that is being used
func (p *Prometheus) ListenAddress(address string) {
	p.listenAddress = address
	if p.listenAddress != "" {
		p.router = gin.Default()
	}
}

// Prometheus contains the metrics gathered by the instance and its path
type Prometheus struct {
	reqCnt, reqDur, reqSz, resSz metricFunc
	router                       *gin.Engine
	listenAddress                string

	ppg PrometheusPushGateway

	accounts gin.Accounts

	MetricsPath string

	urlLabelMappingFn URLLabelMappingFn
}

// PrometheusPushGateway contains the configuration for pushing to a Prometheus pushgateway (optional)
type PrometheusPushGateway struct {
	// Push interval in seconds
	pushIntervalSeconds time.Duration

	// Push Gateway URL in format http://domain:port
	// where JOBNAME can be any string of your choice
	pushGatewayURL string

	// Local metrics URL where metrics are fetched from, this could be ommited in the future
	// if implemented using prometheus common/expfmt instead
	metricsURL string

	// pushgateway job name, defaults to "gin"
	job string
}

func (p *Prometheus) setMetricsPath(e *gin.Engine) {
	if p.listenAddress != "" {
		p.router.GET(p.MetricsPath, prometheusHandler())
		p.runServer()
	} else {
		e.GET(p.MetricsPath, prometheusHandler())
	}
}

func (p *Prometheus) setMetricsPathWithAuth(e *gin.Engine, accounts gin.Accounts) {
	if p.listenAddress != "" {
		p.router.GET(p.MetricsPath, gin.BasicAuth(accounts), prometheusHandler())
		p.runServer()
	} else {
		e.GET(p.MetricsPath, gin.BasicAuth(accounts), prometheusHandler())
	}

}

func (p *Prometheus) runServer() {
	if p.listenAddress != "" {
		go p.router.Run(p.listenAddress)
	}
}

func (p *Prometheus) getMetrics() []byte {
	response, _ := http.Get(p.ppg.metricsURL)

	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)

	return body
}

func (p *Prometheus) getPushGatewayURL() string {
	h, _ := os.Hostname()
	if p.ppg.job == "" {
		p.ppg.job = "gin"
	}
	return p.ppg.pushGatewayURL + "/metrics/job/" + p.ppg.job + "/instance/" + h
}

func (p *Prometheus) sendMetricsToPushGateway(metrics []byte) {
	req, err := http.NewRequest("POST", p.getPushGatewayURL(), bytes.NewBuffer(metrics))
	client := &http.Client{}
	_, err = client.Do(req)
	if err != nil {
		log.Printf("Error sending to push gatway: %s\n", err.Error())
	}
}

func (p *Prometheus) startPushTicker() {
	ticker := time.NewTicker(time.Second * p.ppg.pushIntervalSeconds)
	go func() {
		for range ticker.C {
			p.sendMetricsToPushGateway(p.getMetrics())
		}
	}()
}

func (p *Prometheus) handlerFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.String() == p.MetricsPath {
			c.Next()
			return
		}

		start := time.Now()
		reqSz := computeApproximateRequestSize(c.Request)

		c.Next()

		info := metricInfo{
			method:       sanitizeMethod(c.Request.Method),
			code:         sanitizeCode(c.Writer.Status()),
			url:          p.urlLabelMappingFn(c),
			duration:     float64(time.Since(start)) / float64(time.Second),
			requestSize:  float64(reqSz),
			responseSize: float64(c.Writer.Size()),
		}
		if p.reqCnt != nil {
			p.reqCnt(&info)
		}
		if p.reqDur != nil {
			p.reqDur(&info)
		}
		if p.reqSz != nil {
			p.reqSz(&info)
		}
		if p.resSz != nil {
			p.resSz(&info)
		}
	}
}

func prometheusHandler() gin.HandlerFunc {
	h := promhttp.Handler()
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

// From https://github.com/DanielHeckrath/gin-prometheus/blob/master/gin_prometheus.go
func computeApproximateRequestSize(r *http.Request) int {
	s := 0
	if r.URL != nil {
		s = len(r.URL.String())
	}

	s += len(r.Method)
	s += len(r.Proto)
	for name, values := range r.Header {
		s += len(name)
		for _, value := range values {
			s += len(value)
		}
	}
	s += len(r.Host)

	// N.B. r.Form and r.MultipartForm are assumed to be included in r.URL.

	if r.ContentLength != -1 {
		s += int(r.ContentLength)
	}
	return s
}

var emptyLabels = prometheus.Labels{}

func labels(codeExists, methodExists, urlExists bool, code, method, url string) prometheus.Labels {
	if !(codeExists || methodExists || urlExists) {
		return emptyLabels
	}
	labels := prometheus.Labels{}

	if codeExists {
		labels["code"] = code
	}
	if methodExists {
		labels["method"] = method
	}
	if urlExists {
		labels["url"] = url
	}

	return labels
}

func sanitizeMethod(m string) string {
	switch m {
	case "GET", "get":
		return "get"
	case "PUT", "put":
		return "put"
	case "HEAD", "head":
		return "head"
	case "POST", "post":
		return "post"
	case "DELETE", "delete":
		return "delete"
	case "CONNECT", "connect":
		return "connect"
	case "OPTIONS", "options":
		return "options"
	case "NOTIFY", "notify":
		return "notify"
	default:
		return strings.ToLower(m)
	}
}

// If the wrapped http.Handler has not set a status code, i.e. the value is
// currently 0, santizeCode will return 200, for consistency with behavior in
// the stdlib.
func sanitizeCode(s int) string {
	switch s {
	case 100:
		return "100"
	case 101:
		return "101"

	case 200:
		return "200"
	case 201:
		return "201"
	case 202:
		return "202"
	case 203:
		return "203"
	case 204:
		return "204"
	case 205:
		return "205"
	case 206:
		return "206"

	case 300:
		return "300"
	case 301:
		return "301"
	case 302:
		return "302"
	case 304:
		return "304"
	case 305:
		return "305"
	case 307:
		return "307"

	case 400:
		return "400"
	case 401:
		return "401"
	case 402:
		return "402"
	case 403:
		return "403"
	case 404:
		return "404"
	case 405:
		return "405"
	case 406:
		return "406"
	case 407:
		return "407"
	case 408:
		return "408"
	case 409:
		return "409"
	case 410:
		return "410"
	case 411:
		return "411"
	case 412:
		return "412"
	case 413:
		return "413"
	case 414:
		return "414"
	case 415:
		return "415"
	case 416:
		return "416"
	case 417:
		return "417"
	case 418:
		return "418"

	case 500:
		return "500"
	case 501:
		return "501"
	case 502:
		return "502"
	case 503:
		return "503"
	case 504:
		return "504"
	case 505:
		return "505"

	case 428:
		return "428"
	case 429:
		return "429"
	case 431:
		return "431"
	case 511:
		return "511"

	default:
		return strconv.Itoa(s)
	}
}

func checkLabels(c prometheus.Collector) (code bool, method bool, url bool) {
	// TODO(beorn7): Remove this hacky way to check for instance labels
	// once Descriptors can have their dimensionality queried.
	var (
		desc *prometheus.Desc
		m    prometheus.Metric
		pm   dto.Metric
		lvs  []string
	)

	// Get the Desc from the Collector.
	descc := make(chan *prometheus.Desc, 1)
	c.Describe(descc)

	select {
	case desc = <-descc:
	default:
		panic("no description provided by collector")
	}
	select {
	case <-descc:
		panic("more than one description provided by collector")
	default:
	}

	close(descc)

	// Create a ConstMetric with the Desc. Since we don't know how many
	// variable labels there are, try for as long as it needs.
	for err := errors.New("dummy"); err != nil; lvs = append(lvs, magicString) {
		m, err = prometheus.NewConstMetric(desc, prometheus.UntypedValue, 0, lvs...)
	}

	// Write out the metric into a proto message and look at the labels.
	// If the value is not the magicString, it is a constLabel, which doesn't interest us.
	// If the label is curried, it doesn't interest us.
	// In all other cases, only "code" or "method" is allowed.
	if err := m.Write(&pm); err != nil {
		panic("error checking metric for labels")
	}
	for _, label := range pm.Label {
		name, value := label.GetName(), label.GetValue()
		if value != magicString || isLabelCurried(c, name) {
			continue
		}
		switch name {
		case "code":
			code = true
		case "method":
			method = true
		case "url":
			url = true
		default:
			panic("metric partitioned with non-supported labels")
		}
	}
	return
}

func isLabelCurried(c prometheus.Collector, label string) bool {
	// This is even hackier than the label test above.
	// We essentially try to curry again and see if it works.
	// But for that, we need to type-convert to the two
	// types we use here, ObserverVec or *CounterVec.
	switch v := c.(type) {
	case *prometheus.CounterVec:
		if _, err := v.CurryWith(prometheus.Labels{label: "dummy"}); err == nil {
			return false
		}
	case prometheus.ObserverVec:
		if _, err := v.CurryWith(prometheus.Labels{label: "dummy"}); err == nil {
			return false
		}
	default:
		panic("unsupported metric vec type")
	}
	return true
}
