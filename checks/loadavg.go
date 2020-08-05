package checks

import (
	"fmt"
	"sync"

	pb "git.jba.io/go/gorram/proto"
	"github.com/shirou/gopsutil/load"
)

type loadAvg struct {
	sync.Mutex
	Cfg *pb.Config_LoadAvg
}

func init() {
	theChecks = append(theChecks, &loadAvg{})
}

func (l *loadAvg) configure(cfg pb.Config) error {
	if cfg.GetLoadavg() == nil {
		return errEmptyConfig
	}
	l.Lock()
	l.Cfg = cfg.GetLoadavg()
	l.Unlock()
	return nil
}

func (l *loadAvg) Title() string {
	return "Loadavg"
}

func (l *loadAvg) doCheck() []pb.Issue {
	var issues []pb.Issue

	loadAvgs, err := load.Avg()
	if err != nil {
		issues = append(issues, newIssue(l.Title(), fmt.Sprintf("Error fetching load average, %v", err)))
		return issues
	}

	if loadAvgs.Load15 >= l.Cfg.MaxLoad {
		issues = append(issues, newIssue(l.Title(), fmt.Sprintf("Load average (15) is greater than %f, %f", l.Cfg.MaxLoad, loadAvgs.Load15)))
		return issues
	}

	if loadAvgs.Load5 >= l.Cfg.MaxLoad {
		issues = append(issues, newIssue(l.Title(), fmt.Sprintf("Load average (5) is greater than %f, %f", l.Cfg.MaxLoad, loadAvgs.Load5)))
		return issues
	}

	if loadAvgs.Load1 >= l.Cfg.MaxLoad {
		issues = append(issues, newIssue(l.Title(), fmt.Sprintf("Load average (1) is greater than %f, %f", l.Cfg.MaxLoad, loadAvgs.Load1)))
		return issues
	}

	return issues
}
