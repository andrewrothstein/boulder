package main

import (
	"crypto/sha256"
	"crypto/x509"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
)

type resultHolder struct {
	Serial  string
	Expires time.Time
	DER     []byte
}

type backfiller struct {
	sa    core.StorageAuthority
	dbMap *gorp.DbMap
	stats statsd.Statter
	log   *blog.AuditLogger
}

func new(amqpConf *cmd.AMQPConfig, syslogConf cmd.SyslogConfig, statsdURI, dbURI string) (*backfiller, error) {
	var stats statsd.Statter
	var err error
	stats, log := cmd.StatsAndLogging(cmd.StatsdConfig{Server: statsdURI, Prefix: "Boulder"}, syslogConf)
	sac, err := rpc.NewStorageAuthorityClient("nameset-backfiller", amqpConf, stats)
	if err != nil {
		return nil, err
	}
	dbMap, err := sa.NewDbMap(dbURI)
	if err != nil {
		return nil, err
	}
	return &backfiller{sac, dbMap, stats, log}, nil
}

func (b *backfiller) run() error {
	added := 0
	defer b.log.Info(fmt.Sprintf("Added %d missing certificate name sets to the nameSets table", added))
	for {
		results, err := b.findCerts()
		if err != nil {
			return err
		}
		if len(results) == 0 {
			break
		}
		err = b.processResults(results)
		if err != nil {
			return err
		}
		added += len(results)
	}
	return nil
}

func (b *backfiller) findCerts() ([]resultHolder, error) {
	var results []resultHolder
	_, err := b.dbMap.Select(
		&results,
		// idk left outer join instead?
		`SELECT c.serial, c.expires, c.der FROM certificates AS c
     WHERE c.serial NOT IN (SELECT ns.serial FROM nameSets AS ns)
     AND c.expires > ?
     ORDER BY c.issued DESC
     LIMIT ?`,
		time.Now(), // now
		1000,       // limit
	)
	b.stats.Inc("db-backfill.nameSets.missing-found", int64(len(results)), 1.0)
	return results, err
}

func hashNames(names []string) []byte {
	core.LowerAndSort(names)
	hash := sha256.Sum256([]byte(strings.Join(names, ",")))
	return hash[:]
}

func (b *backfiller) processResults(results []resultHolder) error {
	numResults := len(results)
	added := 0
	for _, r := range results {
		c, err := x509.ParseCertificate(r.DER)
		if err != nil {
			b.log.Err(fmt.Sprintf("Failed to parse certificate retrieved from database: %s", err))
			continue
		}
		err = b.dbMap.Insert(core.NameSet{
			SetHash: hashNames(c.DNSNames),
			Serial:  r.Serial,
			Expires: r.Expires,
		})
		if err != nil {
			b.log.Err(fmt.Sprintf("Failed to add name set to database: %s", err))
			continue
		}
		added++
		b.stats.Inc("db-backfill.nameSets.added", 1, 1.0)
	}
	if added < numResults {
		return fmt.Errorf("Didn'd add all name sets, %d out of %d failed", numResults-added, numResults)
	}
	return nil
}

func main() {
	amqpURI := flag.String("amqpURI", "amqp://guest:guest@localhost:5673", "")
	statsdURI := flag.String("statsdURI", "localhost:8125", "")
	dbURI := flag.String("dbURI", "mysql+tcp://backfiller@localhost:3306/boulder_sa_test", "")
	syslogNet := flag.String("syslogNetwork", "", "")
	syslogServer := flag.String("syslogServer", "", "")
	syslogLevel := flag.Int("syslogLevel", 7, "")
	flag.Parse()

	b, err := new(
		&cmd.AMQPConfig{
			Server:   *amqpURI,
			Insecure: true,
			SA: &cmd.RPCServerConfig{
				Server:     "SA.server",
				RPCTimeout: cmd.ConfigDuration{Duration: time.Second * 15},
			},
		},
		cmd.SyslogConfig{
			Network:     *syslogNet,
			Server:      *syslogServer,
			StdoutLevel: syslogLevel,
		},
		*statsdURI,
		*dbURI,
	)
	cmd.FailOnError(err, "Failed to create backfiller")
	err = b.run()
	cmd.FailOnError(err, "Failed to backfill nameSets table")
}
