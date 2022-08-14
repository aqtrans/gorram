package checks

import (
	"fmt"
	"sync"

	pb "git.jba.io/go/gorram/proto"
	"github.com/shirou/gopsutil/v3/disk"
)

type diskSpace struct {
	sync.Mutex
	Cfg []*pb.Config_DiskSpace
}

func init() {
	theChecks = append(theChecks, &diskSpace{})
}

func (d *diskSpace) Title() string {
	return "Diskspace"
}

func (d *diskSpace) configure(cfg *pb.Config) error {
	if cfg.GetDiskspace() == nil {
		return errEmptyConfig
	}
	d.Lock()
	d.Cfg = cfg.GetDiskspace()
	d.Unlock()
	return nil
}

func (d *diskSpace) doCheck() []*pb.Issue {

	var issues []*pb.Issue

	for _, aDisk := range d.Cfg {
		usage, err := disk.Usage(aDisk.Partition)
		if err != nil {
			//addIssue(issues, d.Title(), fmt.Sprintf("Error getting disk usage for "+aDisk.Partition+":", err))
			issues = append(issues, newIssue(d.Title(), fmt.Sprintf("Error getting disk usage for "+aDisk.Partition+":", err)))
			continue
		}

		//log.Println("DEBUG DiskSpace: ", usage.UsedPercent, usage.String(), usage.Free)

		if aDisk.GetMaxUsage() != 0 {
			if usage.UsedPercent > aDisk.MaxUsage {
				issues = append(issues, newIssue(d.Title(), fmt.Sprintf("Disk usage of %s is greater than %s; currently %s", aDisk.Partition, fmt.Sprintf("%.1f", aDisk.MaxUsage), fmt.Sprintf("%.1f", usage.UsedPercent))))
				continue
			}
			if usage.UsedPercent == aDisk.MaxUsage {
				issues = append(issues, newIssue(d.Title(), fmt.Sprintf("Disk usage of %s is at %s; currently %s", aDisk.Partition, fmt.Sprintf("%.1f", aDisk.MaxUsage), fmt.Sprintf("%.1f", usage.UsedPercent))))
				continue
			}
		}

		if aDisk.GetMinFreeGb() != 0 {
			// Calculate the given GB to bytes:
			minBytes := aDisk.MinFreeGb * 1000000000
			if usage.Free < uint64(minBytes) {
				freeGB := usage.Free / 1000000000
				issues = append(issues, newIssue(d.Title(), fmt.Sprintf("Free space of %s is less than %v GB; currently %v GB", aDisk.Partition, aDisk.MinFreeGb, freeGB)))
				continue
			}
			if usage.Free == uint64(minBytes) {
				freeGB := usage.Free / 1000000000
				issues = append(issues, newIssue(d.Title(), fmt.Sprintf("Disk usage of %s is at %v GB; currently %v GB", aDisk.Partition, aDisk.MinFreeGb, freeGB)))
				continue
			}
		}
	}
	return issues
}
