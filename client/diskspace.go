package main

import (
	"fmt"
	"log"
	"time"

	"github.com/shirou/gopsutil/disk"
	pb "jba.io/go/gorram/proto"
)

type diskspace struct {
	Partitions []string
	MaxUsage   float64
}

func (p diskspace) doCheck() *checkData {
	var issues []*pb.Issue
	isOK := true

	for _, partition := range p.Partitions {
		usage, err := disk.Usage(partition)
		if err != nil {
			log.Println("Error getting disk usage:", err)
			return nil
		}
		if usage.UsedPercent > p.MaxUsage {
			issues = append(issues, &pb.Issue{
				Message:       fmt.Sprintf("Disk usage of %s is greater than %f, %f", partition, p.MaxUsage, usage.UsedPercent),
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
