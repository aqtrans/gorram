package checks

import (
	"fmt"

	pb "git.jba.io/go/gorram/proto"
	"github.com/shirou/gopsutil/disk"
)

type DiskSpace struct {
	Cfg []*pb.Config_DiskSpace
}

func init() {
	TheChecks = append(TheChecks, &DiskSpace{})
}

func (d DiskSpace) Title() string {
	return "Diskspace"
}

func (d *DiskSpace) configure(cfg *pb.Config) {
	d.Cfg = cfg.GetDiskspace()
}

func (d DiskSpace) doCheck(issues *[]pb.Issue) {

	for _, aDisk := range d.Cfg {
		usage, err := disk.Usage(aDisk.Partition)
		if err != nil {
			addIssue(issues, d.Title(), fmt.Sprintf("Error getting disk usage for "+aDisk.Partition+":", err))
			continue
		}

		//log.Println("DEBUG DiskSpace: ", usage.UsedPercent, usage.String(), usage.Free)

		if aDisk.GetMaxUsage() != 0 {
			if usage.UsedPercent > aDisk.MaxUsage {
				addIssue(issues, d.Title(), fmt.Sprintf("Disk usage of %s is greater than %s; currently %s", aDisk.Partition, fmt.Sprintf("%.1f", aDisk.MaxUsage), fmt.Sprintf("%.1f", usage.UsedPercent)))
				continue
			}
			if usage.UsedPercent == aDisk.MaxUsage {
				addIssue(issues, d.Title(), fmt.Sprintf("Disk usage of %s is at %s; currently %s", aDisk.Partition, fmt.Sprintf("%.1f", aDisk.MaxUsage), fmt.Sprintf("%.1f", usage.UsedPercent)))
				continue
			}
		}

		if aDisk.GetMinFreeGb() != 0 {
			// Calculate the given GB to bytes:
			minBytes := aDisk.MinFreeGb * 1000000000
			if usage.Free < minBytes {
				freeGB := usage.Free / 1000000000
				addIssue(issues, d.Title(), fmt.Sprintf("Free space of %s is less than %v GB; currently %v GB", aDisk.Partition, aDisk.MinFreeGb, freeGB))
				continue
			}
			if usage.Free == minBytes {
				freeGB := usage.Free / 1000000000
				addIssue(issues, d.Title(), fmt.Sprintf("Disk usage of %s is at %v GB; currently %v GB", aDisk.Partition, aDisk.MinFreeGb, freeGB))
				continue
			}
		}
	}
}
