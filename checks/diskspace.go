package checks

import (
	"fmt"
	"log"
	"time"

	"github.com/shirou/gopsutil/disk"
	pb "jba.io/go/gorram/proto"
)

type DiskSpace struct {
	Cfg pb.DiskSpace
}

func (p DiskSpace) doCheck() *checkData {

	usage, err := disk.Usage(p.Cfg.Partition)
	if err != nil {
		log.Println("Error getting disk usage:", err)
		return nil
	}
	if usage.UsedPercent > p.Cfg.MaxUsage {
		return &checkData{
			issue: &pb.Issue{
				Title:         "Disk Usage",
				Message:       fmt.Sprintf("Disk usage of %s is greater than %f, %f", p.Cfg.Partition, p.Cfg.MaxUsage, usage.UsedPercent),
				TimeSubmitted: time.Now().Unix(),
			},
			ok: false,
		}
	}

	return &checkData{
		ok: true,
	}

}
