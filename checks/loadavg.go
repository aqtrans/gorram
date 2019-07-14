package checks

import (
	"fmt"

	pb "git.jba.io/go/gorram/proto"
	"github.com/shirou/gopsutil/load"
)

type loadAvg struct {
	Cfg *pb.Config_LoadAvg
}

func init() {
	theChecks = append(theChecks, &loadAvg{})
}

func (l *loadAvg) configure(cfg *pb.Config) error {
	if cfg.GetLoadavg() == nil {
		return errEmptyConfig
	}
	l.Cfg = cfg.GetLoadavg()
	return nil
}

func (l loadAvg) Title() string {
	return "Loadavg"
}

func (l loadAvg) doCheck() []pb.Issue {
	var issues []pb.Issue

	loadAvgs, err := load.Avg()
	if err != nil {
		issues = append(issues, newIssue(l.Title(), fmt.Sprintf("Error fetching load average, %v", err)))
		return issues
	}

	if loadAvgs.Load15 >= l.Cfg.MaxLoad {
		issues = append(issues, newIssue(l.Title(), fmt.Sprintf("Load average is greater than %f, %f", l.Cfg.MaxLoad, loadAvgs.Load1)))
	}

	if loadAvgs.Load5 >= l.Cfg.MaxLoad {
		issues = append(issues, newIssue(l.Title(), fmt.Sprintf("Load average is greater than %f, %f", l.Cfg.MaxLoad, loadAvgs.Load5)))
	}

	if loadAvgs.Load1 >= l.Cfg.MaxLoad {
		issues = append(issues, newIssue(l.Title(), fmt.Sprintf("Load average is greater than %f, %f", l.Cfg.MaxLoad, loadAvgs.Load1)))
	}

	return issues
}
