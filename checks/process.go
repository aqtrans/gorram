package checks

import (
	"fmt"
	"log"
	"time"

	"github.com/shirou/gopsutil/process"
	pb "jba.io/go/gorram/proto"
)

type ProcessExists struct {
	Names []string
}

func getProcList() map[string]bool {
	procs, err := process.Processes()
	if err != nil {
		log.Fatalln("Error fetching process list", err)
		return nil
	}
	procMap := make(map[string]bool)
	for _, proc := range procs {
		name, err := proc.Name()
		if err != nil {
			log.Println("Error with process name", err, proc.Pid)
			break
		}
		procMap[name] = true
	}
	return procMap
}

func (p ProcessExists) doCheck() *checkData {
	var issues []*pb.Issue
	isOK := true

	procList := getProcList()

	for _, expectedName := range p.Names {
		if !procList[expectedName] {
			issues = append(issues, &pb.Issue{
				Title:         "Process Exists",
				Message:       fmt.Sprintf("%v is not running", expectedName),
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
