package checks

import (
	"errors"

	"github.com/aqtrans/gorram/proto"
	log "github.com/sirupsen/logrus"
)

var theChecks []check

var errEmptyConfig = errors.New("config is empty")

/*
Each check should implement the following interface

- doCheck() is where the actual 'check' should be done, and return an array of checkIssues, either nil or not.
Note it is an array, so one check instance may return multiple errors.
This is useful in disk space and process checks, where multiple disks or processes can produce errors

- Title spits out the Title of the given check, mainly for purposes of alerting.

- configure() takes in the full server config and configures an instance of the check.
If the server config doesn't have an instance of the check config, it returns errEmptyConfig.
This is done so that DoChecks has some mechanism of knowing which checks to do.
*/
type check interface {
	doCheck() []*proto.Issue
	Title() string
	configure(cfg *proto.Config) error
}

// getCheck is a function which all checks should run through.
// It should only be called via DoChecks().
/*
func getCheck(issues []gorram.Issue, c check) []gorram.Issue {
	c.doCheck()
	return issues
}
*/

func newIssue(title, msg string) *proto.Issue {
	return &proto.Issue{
		Title:   title,
		Message: msg,
	}
}

/*
func addIssue(issues *[]gorram.Issue, title, msg string) {
	*issues = append(*issues, gorram.Issue{
		Title:   title,
		Message: msg,
	})
}
*/

// DoChecks is where all the actual checks are done, and an array of "issues" is made
func DoChecks(cfg *proto.Config) []*proto.Issue {
	var issues []*proto.Issue

	// Loop over the available checks and the client's enabled checks
	// If the client has an available check enabled, run it
	/*
		enabledChecks := strings.Split(cfg.EnabledChecks, ",")
		for _, ec := range enabledChecks {
			for _, c := range theChecks {
				if ec == c.Title() {
					log.Println(ec, "is enabled! Running check...")
					log.Println(cfg.Process)
					c.configure(cfg)
					issues = getCheck(issues, c)
				}
			}
		}
	*/
	for _, c := range theChecks {
		err := c.configure(cfg)
		if err == nil {
			log.Debugln("Config not empty. Running check", c.Title())
			checkIssues := c.doCheck()
			if checkIssues != nil {
				issues = append(issues, checkIssues...)
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
