package checks

import (
	"fmt"

	pb "git.jba.io/go/gorram/proto"
	"github.com/shirou/gopsutil/mem"
)

type memory struct {
	Cfg *pb.Config_Memory
}

func init() {
	theChecks = append(theChecks, &memory{})
}

func (m *memory) configure(cfg *pb.Config) error {
	if cfg.GetMemory() == nil {
		return errEmptyConfig
	}
	m.Cfg = cfg.GetMemory()
	return nil
}

func (m memory) Title() string {
	return "Memory"
}

func (m memory) doCheck() []pb.Issue {
	var issues []pb.Issue

	vmStat, err := mem.VirtualMemory()
	if err != nil {
		issues = append(issues, newIssue(m.Title(), fmt.Sprintf("Error fetching virtual memory stats, %v", err)))
		return issues
	}
	if vmStat.UsedPercent >= m.Cfg.MaxUsage {
		issues = append(issues, newIssue(m.Title(), fmt.Sprintf("Used memory %% is greater than %f, %f", m.Cfg.MaxUsage, vmStat.UsedPercent)))
	}

	return issues

}
