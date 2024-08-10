package checks

//USAGE: ./check-deluge -n [max number of torrents] -p [password for Deluge web ui]
//This is a replacement for my bash-powered Deluge Sensu check, which was just using `deluge-console|grep`
//It takes advantage of the Deluge WebUI JSON API
//To keep things simple, it sets a bool variable to true, which is finally what determines the exit status of the program, telling Sensu what to do

import (
	"fmt"
	"strconv"
	"sync"

	delugeclient "github.com/gdm85/go-libdeluge"

	pb "github.com/aqtrans/gorram/proto"
)

var badMsg string

type delugeCheck struct {
	sync.Mutex
	Cfg *pb.Config_Deluge
}

func init() {
	theChecks = append(theChecks, &delugeCheck{})
}

func (d *delugeCheck) configure(cfg *pb.Config) error {
	if cfg.GetDeluge() == nil {
		return errEmptyConfig
	}
	d.Lock()
	d.Cfg = cfg.GetDeluge()
	d.Unlock()
	return nil
}

func (d *delugeCheck) Title() string {
	return "Deluge"
}

func (d *delugeCheck) doCheck() []*pb.Issue {

	// you can use NewV1 to create a client for Deluge v1.3
	delugeClient := delugeclient.NewV2(delugeclient.Settings{
		Hostname: d.Cfg.Hostname,
		Port:     uint(d.Cfg.Port),
		Login:    d.Cfg.Username,
		Password: d.Cfg.Password,
	})

	defer delugeClient.Close()

	// perform connection to Deluge server
	err := delugeClient.Connect()
	if err != nil {
		return []*pb.Issue{newIssue(d.Title(), fmt.Sprintf("error connecting to Deluge: %v", err))}
	}
	torrents, err := delugeClient.TorrentsStatus(delugeclient.StateUnspecified, nil)
	if err != nil {
		return []*pb.Issue{newIssue(d.Title(), fmt.Sprintf("error getting torrents status: %v", err))}
	}

	var dlcnt int64
	var chkcnt int64
	var errcnt int64

	for _, v := range torrents {
		if v.State == string(delugeclient.StateDownloading) {
			dlcnt += 1
		}
		if v.State == string(delugeclient.StateError) {
			errcnt += 1
		}
		if v.State == string(delugeclient.StateChecking) {
			chkcnt += 1
		}
	}

	var issues []*pb.Issue
	if dlcnt > d.Cfg.MaxTorrents {
		badMsg = strconv.FormatInt(dlcnt, 10) + " downloading torrents is too many."
		issues = append(issues, newIssue(d.Title(), badMsg))
	}
	if chkcnt > d.Cfg.MaxTorrents {
		badMsg = strconv.FormatInt(chkcnt, 10) + " checking torrents is too many."
		issues = append(issues, newIssue(d.Title(), badMsg))
	}
	if errcnt > d.Cfg.MaxTorrents {
		badMsg = strconv.FormatInt(errcnt, 10) + " errored torrents is too many."
		issues = append(issues, newIssue(d.Title(), badMsg))
	}
	//fmt.Println(isBad)
	//fmt.Println(badMsg)

	return issues
}
