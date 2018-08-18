package checks

import (
	"time"

	gorram "git.jba.io/go/gorram/proto"
)

type checkData struct {
	issue *gorram.Issue
}

type check interface {
	doCheck() string
	title() string
}

/*
type Config struct {
	Interval int64
	Load     *LoadAvg
	Disk     *DiskSpace
	Deluge   *DelugeCheck
	Ps       *ProcessExists
}
*/

// GetCheck is a function which all checks should run through
// It should only be called in client.go by doCheck().
// If the check() is not OK, it appends the issues and returns it.
func GetCheck(issues []*gorram.Issue, c check) []*gorram.Issue {
	//log.Println("Check:", c)
	theCheck := c.doCheck()
	if theCheck != "" {
		issues = append(issues, &gorram.Issue{
			Title:         c.title(),
			Message:       theCheck,
			TimeSubmitted: time.Now().Unix(),
		})
	}
	return issues
}
