package checks

import (
	gorram "jba.io/go/gorram/proto"
)

type checkData struct {
	issues []*gorram.Issue
	ok     bool
}

type check interface {
	doCheck() *checkData
}

type Config struct {
	Load   *LoadAvg
	Disk   *DiskSpace
	Deluge *DelugeCheck
}

// GetCheck is a function which all checks should run through
// It should only be called in client.go by doCheck().
// If the check() is not OK, it appends the issues and returns it.
func GetCheck(checks []*gorram.Issue, c check) []*gorram.Issue {
	//log.Println("Check:", c)
	theCheck := c.doCheck()
	if !theCheck.ok {
		for _, issue := range theCheck.issues {
			checks = append(checks, issue)
		}
	}
	return checks
}
