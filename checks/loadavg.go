package checks

import (
	"fmt"

	pb "git.jba.io/go/gorram/proto"
	"github.com/shirou/gopsutil/load"
)

type LoadAvg struct {
	Cfg *pb.Config_LoadAvg
}

func init() {
	TheChecks = append(TheChecks, &LoadAvg{})
}

func (l *LoadAvg) configure(cfg *pb.Config) {
	l.Cfg = cfg.GetLoadavg()
}

func (l LoadAvg) Title() string {
	return "Loadavg"
}

func (l LoadAvg) doCheck(issues *[]pb.Issue) {

	loadAvgs, err := load.Avg()
	if err != nil {
		addIssue(issues, l.Title(), fmt.Sprintf("Error fetching load average, %v", err))
		return
	}

	if loadAvgs.Load15 >= l.Cfg.MaxLoad {
		addIssue(issues, l.Title(), fmt.Sprintf("Load average is greater than %f, %f", l.Cfg.MaxLoad, loadAvgs.Load1))
		return
	}

	if loadAvgs.Load5 >= l.Cfg.MaxLoad {
		addIssue(issues, l.Title(), fmt.Sprintf("Load average is greater than %f, %f", l.Cfg.MaxLoad, loadAvgs.Load5))
		return
	}

	if loadAvgs.Load1 >= l.Cfg.MaxLoad {
		addIssue(issues, l.Title(), fmt.Sprintf("Load average is greater than %f, %f", l.Cfg.MaxLoad, loadAvgs.Load1))
		return
	}
}
