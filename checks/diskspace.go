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
	var issues []*pb.Issue
	isOK := true

	for _, partition := range p.Cfg.Partitions {
		usage, err := disk.Usage(partition)
		if err != nil {
			log.Println("Error getting disk usage:", err)
			return nil
		}
		if usage.UsedPercent > p.Cfg.MaxUsage {
			issues = append(issues, &pb.Issue{
				Title:         "Disk Usage",
				Message:       fmt.Sprintf("Disk usage of %s is greater than %f, %f", partition, p.Cfg.MaxUsage, usage.UsedPercent),
				TimeSubmitted: time.Now().Unix(),
			})
			isOK = false
		}
	}

	return &checkData{
		issues: issues,
		ok:     isOK,
	}

}
