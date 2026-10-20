package metrics

import (
	"database/sql"

	"github.com/prometheus/client_golang/prometheus"
)

// dbStatsCollector implements prometheus.Collector for sql.DB pool statistics.
// It reads stats on each Prometheus scrape, so values are always fresh.
type dbStatsCollector struct {
	db *sql.DB

	openDesc    *prometheus.Desc
	inUseDesc   *prometheus.Desc
	idleDesc    *prometheus.Desc
	waitDesc    *prometheus.Desc
	waitDurDesc *prometheus.Desc
}

// RegisterDBStatsCollector registers a collector that reports sql.DB pool
// statistics on each Prometheus scrape.
func RegisterDBStatsCollector(reg *prometheus.Registry, db *sql.DB) {
	reg.MustRegister(&dbStatsCollector{
		db: db,
		openDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db_pool", "open_connections"),
			"Number of open database connections.",
			nil, nil,
		),
		inUseDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db_pool", "in_use_connections"),
			"Number of database connections currently in use.",
			nil, nil,
		),
		idleDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db_pool", "idle_connections"),
			"Number of idle database connections.",
			nil, nil,
		),
		waitDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db_pool", "wait_count_total"),
			"Total number of connections waited for.",
			nil, nil,
		),
		waitDurDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db_pool", "wait_duration_seconds_total"),
			"Total time spent waiting for database connections.",
			nil, nil,
		),
	})
}

func (c *dbStatsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.openDesc
	ch <- c.inUseDesc
	ch <- c.idleDesc
	ch <- c.waitDesc
	ch <- c.waitDurDesc
}

func (c *dbStatsCollector) Collect(ch chan<- prometheus.Metric) {
	stats := c.db.Stats()

	ch <- prometheus.MustNewConstMetric(c.openDesc, prometheus.GaugeValue, float64(stats.OpenConnections))
	ch <- prometheus.MustNewConstMetric(c.inUseDesc, prometheus.GaugeValue, float64(stats.InUse))
	ch <- prometheus.MustNewConstMetric(c.idleDesc, prometheus.GaugeValue, float64(stats.Idle))
	ch <- prometheus.MustNewConstMetric(c.waitDesc, prometheus.CounterValue, float64(stats.WaitCount))
	ch <- prometheus.MustNewConstMetric(c.waitDurDesc, prometheus.CounterValue, stats.WaitDuration.Seconds())
}
