package checks

import (
	"log"

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

// GetCheck() is a function which all Checks should run through
// It should only be called above by doCheck().
// If the check() is not OK, it appends the issues and returns it.
func GetCheck(checks []*gorram.Issue, c check) []*gorram.Issue {
	//log.Println("Check:", c)
	theCheck := c.doCheck()
	if !theCheck.ok {
		log.Println("Check is not OK:", theCheck.issues)
		for _, issue := range theCheck.issues {
			log.Println(issue.Message)
			checks = append(checks, issue)
		}
	}
	return checks
}
