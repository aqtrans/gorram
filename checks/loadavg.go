package checks

import (
	"fmt"

	"github.com/shirou/gopsutil/load"
	pb "jba.io/go/gorram/proto"
)

type LoadAvg struct {
	Cfg pb.Load
}

func (l LoadAvg) title() string {
	return "Load Avg"
}

func (l LoadAvg) doCheck() string {

	loadAvgs, err := load.Avg()
	if err != nil {
		return fmt.Sprintf("Error fetching load average, %v", err)
	}

	if loadAvgs.Load15 >= l.Cfg.MaxLoad {

		return fmt.Sprintf("Load average is greater than %f, %f", l.Cfg.MaxLoad, loadAvgs.Load1)
	}

	if loadAvgs.Load5 >= l.Cfg.MaxLoad {

		return fmt.Sprintf("Load average is greater than %f, %f", l.Cfg.MaxLoad, loadAvgs.Load5)
	}

	if loadAvgs.Load1 >= l.Cfg.MaxLoad {

		return fmt.Sprintf("Load average is greater than %f, %f", l.Cfg.MaxLoad, loadAvgs.Load1)
	}

	return ""
}
