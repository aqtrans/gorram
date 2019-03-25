package checks

import (
	"fmt"

	pb "git.jba.io/go/gorram/proto"
	"github.com/shirou/gopsutil/mem"
)

type Memory struct {
	Cfg *pb.Config_Memory
}

func init() {
	TheChecks = append(TheChecks, &Memory{})
}

func (m *Memory) configure(cfg *pb.Config) {
	m.Cfg = cfg.GetMemory()
}

func (m Memory) Title() string {
	return "Memory"
}

func (m Memory) doCheck(issues *[]pb.Issue) {

	vmStat, err := mem.VirtualMemory()
	if err != nil {
		addIssue(issues, m.Title(), fmt.Sprintf("Error fetching virtual memory stats, %v", err))
		return
	}
	if vmStat.UsedPercent >= m.Cfg.MaxUsage {
		addIssue(issues, m.Title(), fmt.Sprintf("Used memory %% is greater than %f, %f", m.Cfg.MaxUsage, vmStat.UsedPercent))
		return
	}

}
