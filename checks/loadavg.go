package checks

import (
	"fmt"
	"time"

	"github.com/shirou/gopsutil/load"
	pb "jba.io/go/gorram/proto"
)

type LoadAvg struct {
	Cfg pb.Load
}

func (l LoadAvg) doCheck() *checkData {

	loadAvgs, err := load.Avg()
	if err != nil {
		return &checkData{
			issue: &pb.Issue{
				Title:         "Load Average",
				Message:       fmt.Sprintf("Error fetching load average, %v", err),
				TimeSubmitted: time.Now().Unix(),
			},
			ok: false,
		}
	}

	if loadAvgs.Load15 >= l.Cfg.MaxLoad {

		return &checkData{
			issue: &pb.Issue{
				Title:         "Load Average",
				Message:       fmt.Sprintf("Load average is greater than %f, %f", l.Cfg.MaxLoad, loadAvgs.Load1),
				TimeSubmitted: time.Now().Unix(),
			},
			ok: false,
		}
	}

	if loadAvgs.Load5 >= l.Cfg.MaxLoad {

		return &checkData{
			issue: &pb.Issue{
				Title:         "Load Average",
				Message:       fmt.Sprintf("Load average is greater than %f, %f", l.Cfg.MaxLoad, loadAvgs.Load5),
				TimeSubmitted: time.Now().Unix(),
			},
			ok: false,
		}
	}

	if loadAvgs.Load1 >= l.Cfg.MaxLoad {

		return &checkData{
			issue: &pb.Issue{
				Title:         "Load Average",
				Message:       fmt.Sprintf("Load average is greater than %f, %f", l.Cfg.MaxLoad, loadAvgs.Load1),
				TimeSubmitted: time.Now().Unix(),
			},
			ok: false,
		}
	}

	return &checkData{
		ok: true,
	}
}
