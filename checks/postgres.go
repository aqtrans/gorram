package checks

import (
	"database/sql"
	"fmt"
	"log"
	"sync"

	proto "git.jba.io/go/gorram/proto"
	_ "github.com/lib/pq"
)

type postgres struct {
	sync.Mutex
	Cfg *proto.Config_Postgres
}

func init() {
	theChecks = append(theChecks, &postgres{})
}

func (p *postgres) configure(cfg proto.Config) error {
	if cfg.GetPostgres() == nil {
		return errEmptyConfig
	}
	p.Lock()
	p.Cfg = cfg.GetPostgres()
	p.Unlock()
	return nil
}

func (p *postgres) Title() string {
	return "Postgres"
}

func (p *postgres) doCheck() []proto.Issue {
	var issues []proto.Issue

	connStr := p.Cfg.ConnectString
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	var clientState string
	err = db.QueryRow("SELECT client_addr, state FROM pg_stat_replication WHERE client_addr=?", p.Cfg.ClientAddress).Scan(&clientState)
	if err == sql.ErrNoRows {
		issues = append(issues, newIssue(p.Title(), fmt.Sprintf("Postgres replication is not functional")))
	}
	if err != nil {
		issues = append(issues, newIssue(p.Title(), fmt.Sprintf("Error fetching Postgres replication stats, %v", err)))
		db.Close()
		return issues
	}

	db.Close()
	return issues

}
