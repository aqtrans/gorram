package checks

import (
	"log"
	"strings"

	gorram "git.jba.io/go/gorram/proto"
)

type checkData struct {
	issue *gorram.Issue
}

var TheChecks []check

type check interface {
	doCheck(*[]gorram.Issue)
	Title() string
	//Do([]gorram.Issue) []gorram.Issue
	configure(cfg *gorram.Config)
	//configure(*[]gorram.Issue, *gorram.Config_Checks)
}

// GetCheck is a function which all checks should run through
// It should only be called in client.go by doCheck().
// If the check() is not OK, it appends the issues and returns it.
func getCheck(issues []gorram.Issue, c check) []gorram.Issue {
	//log.Println("Check:", c)
	c.doCheck(&issues)
	/*
		if theCheck != "" {
			issues = append(issues, gorram.Issue{
				Title:   c.Title(),
				Message: theCheck,
			})
		}
	*/
	return issues
}

func addIssue(issues *[]gorram.Issue, title, msg string) {
	*issues = append(*issues, gorram.Issue{
		Title:   title,
		Message: msg,
	})
}

// DoChecks is where all the actual checks are done, and an array of "issues" is made
func DoChecks(cfg *gorram.Config) []gorram.Issue {
	var issues []gorram.Issue

	enabledChecks := strings.Split(cfg.EnabledChecks, ",")

	// Loop over the available checks and the client's enabled checks
	// If the client has an available check enabled, run it
	for _, ec := range enabledChecks {
		for _, c := range TheChecks {
			if ec == c.Title() {
				log.Println(ec, "is enabled! Running check...")
				c.configure(cfg)
				issues = getCheck(issues, c)
			}
		}
	}

	/*
		// Check loadavg
		if cfg.Load != nil {
			issues = getCheck(issues, LoadAvg{Cfg: *cfg.Load})
		}
		// Check disk usage, looping through given list of disks
		if cfg.Disk != nil {
			for _, diskCheck := range cfg.Disk {
				issues = getCheck(issues, DiskSpace{Cfg: *diskCheck})
			}
		}
		// Check Deluge
		if cfg.Deluge != nil {
			issues = getCheck(issues, DelugeCheck{Cfg: *cfg.Deluge})
		}
		// Check ps faux, looping through given list of full process names
		if cfg.Ps != nil {
			for _, psCheck := range cfg.Ps {
				issues = getCheck(issues, ProcessExists{Cfg: *psCheck})
			}
		}
		// Check GET URLs, looping throug list of given URLs
		if cfg.GetUrl != nil {
			for _, urlCheck := range cfg.GetUrl {
				issues = getCheck(issues, GetURL{Cfg: *urlCheck})
			}
		}
	*/

	return issues
}
