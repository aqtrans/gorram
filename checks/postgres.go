package checks

import (
	"fmt"
	"sync"

	proto "git.jba.io/go/gorram/proto"
	"github.com/go-pg/pg/v9"
)

type postgres struct {
	sync.Mutex
	Cfg *proto.Config_Postgres
}

type replicationStatus struct {
	state string
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

	db := pg.Connect(&pg.Options{
		User:     p.Cfg.User,
		Addr:     p.Cfg.Address,
		Password: p.Cfg.Password,
		Database: "postgres",
	})
	defer db.Close()

	var stats replicationStatus
	err := db.Model(&stats).Select()
	if err != nil {
		issues = append(issues, newIssue(p.Title(), fmt.Sprintf("Error fetching Postgres replication stats, %v", err)))
		return issues
	}
	if stats.state == "" {
		issues = append(issues, newIssue(p.Title(), fmt.Sprintf("Postgres replication is not functional")))
	}

	return issues

}
