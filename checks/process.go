package checks

import (
	"fmt"
	"log"
	"strings"

	pb "git.jba.io/go/gorram/proto"
	"github.com/shirou/gopsutil/process"
)

type ProcessExists struct {
	Cfg []*pb.Config_ProcessExists
}

func init() {
	TheChecks = append(TheChecks, &ProcessExists{})
}

func (p *ProcessExists) configure(cfg *pb.Config) {
	p.Cfg = cfg.GetProcess()
}

func checkForProc(c pb.Config_ProcessExists) bool {
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

func (p ProcessExists) Title() string {
	return "Process"
}

func (p ProcessExists) doCheck(issues *[]pb.Issue) {
	//procList := getProcList()

	for _, psCheck := range p.Cfg {
		log.Println(psCheck)
		if !checkForProc(*psCheck) {
			addIssue(issues, p.Title(), fmt.Sprintf("%v is not running. Check that the full path is specified.", psCheck.Path))
		}
	}
}
