package checks

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/shirou/gopsutil/process"
	pb "jba.io/go/gorram/proto"
)

type ProcessExists struct {
	Cfg pb.ProcessExists
}

func checkForProc(c pb.ProcessExists) bool {
	var procExists bool

	procs, err := process.Processes()
	if err != nil {
		log.Fatalln("Error fetching process list", err)
		return false
	}
	for _, proc := range procs {
		// Don't try to read PID 1
		if proc.Pid == 1 {
			continue
		}
		// Recording full executable path, using Cmdline() instead of Name() here:
		name, err := proc.Cmdline()
		if err != nil {
			log.Println("error retrieving cmdline for proc", err)
			continue
		}
		// Using strings.Contains() here to allow partial matching, for Nginx, Sidekiq, and others that use fancy /proc/$PID/cmdline's
		if strings.Contains(name, c.Path) {
			if c.User != "" {
				user, err := proc.Username()
				if err != nil {
					log.Println("error retrieving user for proc", err)
					continue
				}

				if user == c.User {
					procExists = true
					break
				}
			} else {
				procExists = true
				break
			}
		}
	}
	return procExists
}

func (p ProcessExists) doCheck() *checkData {
	//procList := getProcList()

	if !checkForProc(p.Cfg) {
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
