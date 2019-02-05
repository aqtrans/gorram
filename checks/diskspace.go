package checks

import (
	"fmt"
	"log"

	pb "git.jba.io/go/gorram/proto"
	"github.com/shirou/gopsutil/disk"
)

type DiskSpace struct {
	Cfg pb.DiskSpace
}

func (p DiskSpace) title() string {
	return "Disk Space"
}

func (p DiskSpace) doCheck() string {

	usage, err := disk.Usage(p.Cfg.Partition)
	if err != nil {
		log.Println("Error getting disk usage for "+p.Cfg.Partition+":", err)
		return ""
	}
	log.Println("DEBUG DiskSpace: ", usage.UsedPercent, usage.String(), usage.Free)
	if usage.UsedPercent > p.Cfg.MaxUsage {
		return fmt.Sprintf("Disk usage of %s is greater than %f, %f", p.Cfg.Partition, p.Cfg.MaxUsage, usage.UsedPercent)
	}
	if usage.UsedPercent == p.Cfg.MaxUsage {
		return fmt.Sprintf("Disk usage of %s is at %f, %f", p.Cfg.Partition, p.Cfg.MaxUsage, usage.UsedPercent)
	}

	return ""

}
