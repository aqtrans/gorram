package checks

import (
	"fmt"
	"log"
	"time"

	"github.com/shirou/gopsutil/process"
	pb "jba.io/go/gorram/proto"
)

type ProcessExists struct {
	Cfg pb.ProcessExists
}

func getProcList() map[string]bool {
	procs, err := process.Processes()
	if err != nil {
		log.Fatalln("Error fetching process list", err)
		return nil
	}
	procMap := make(map[string]bool)
	for _, proc := range procs {
		// Don't try to read PID 1
		if proc.Pid == 1 {
			continue
		}
		// Recording full executable path, using Cmdline() instead of Name() here:
		name, err := proc.Cmdline()
		if err != nil {
			continue
		}
		procMap[name] = true
	}
	return procMap
}

func (p ProcessExists) doCheck() *checkData {
	procList := getProcList()

	if !procList[p.Cfg.Path] {
		return &checkData{
			issue: &pb.Issue{
				Title:         "Process Exists",
				Message:       fmt.Sprintf("%v is not running. Check that the full path is specified.", p.Cfg.Path),
				TimeSubmitted: time.Now().Unix(),
			},
			ok: false,
		}
	}

	return &checkData{
		ok: true,
	}
}
