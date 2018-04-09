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
		// Recording full executable path, using Exe() instead of Name() here:
		name, err := proc.Exe()
		if err != nil {
			continue
		}
		procMap[name] = true
	}
	return procMap
}

func (p ProcessExists) doCheck() *checkData {
	var issues []*pb.Issue
	isOK := true

	procList := getProcList()

	log.Println(procList)

	for _, expectedName := range p.Cfg.FullPaths {
		if !procList[expectedName] {
			issues = append(issues, &pb.Issue{
				Title:         "Process Exists",
				Message:       fmt.Sprintf("%v is not running. Check that the full path is specified.", expectedName),
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
