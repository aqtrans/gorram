package checks

import (
	"fmt"
	"strings"
	"sync"

	pb "git.jba.io/go/gorram/proto"
	"github.com/shirou/gopsutil/process"
	log "github.com/sirupsen/logrus"
)

type processExists struct {
	sync.Mutex
	Cfg []*pb.Config_ProcessExists
}

func init() {
	theChecks = append(theChecks, &processExists{})
}

func (p *processExists) configure(cfg *pb.Config) error {
	if cfg.GetProcess() == nil {
		return errEmptyConfig
	}
	p.Lock()
	p.Cfg = cfg.GetProcess()
	p.Unlock()
	return nil
}

func checkForProc(c *pb.Config_ProcessExists) bool {
	var procExists bool

	procs, err := process.Processes()
	if err != nil {
		log.Errorln("Error fetching process list", err)
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
			log.Debugln("Error retrieving cmdline for proc", err)
			continue
		}
		// Using strings.Contains() here to allow partial matching, for Nginx, Sidekiq, and others that use fancy /proc/$PID/cmdline's
		if strings.Contains(name, c.Path) {
			if c.User != "" {
				user, err := proc.Username()
				if err != nil {
					log.Debugln("Error retrieving user for proc", err)
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

func (p *processExists) Title() string {
	return "Process"
}

func (p *processExists) doCheck() []*pb.Issue {
	var issues []*pb.Issue
	//procList := getProcList()

	for _, psCheck := range p.Cfg {
		if !checkForProc(psCheck) {
			issues = append(issues, newIssue(p.Title(), fmt.Sprintf("%v is not running. Check that the full path is specified.", psCheck.Path)))
		}
	}

	return issues
}
