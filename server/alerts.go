package main

import (
	"encoding/base64"
	"time"

	pb "git.jba.io/go/gorram/proto"
	log "github.com/sirupsen/logrus"
)

// sendAlert() decides whether to send alerts
// // Uses a very basic cooloff method:
// // - always under 5
// // - less than 50 and divisible by 10
// // - greater than 50 and divisible by 50
// // - greater than 500 and divisible by 100
func sendAlert(i int64) bool {
	if i < 5 {
		return true
	}
	if i < 50 && (i%10) == 0 {
		return true
	}
	if i > 500 && (i%100) == 0 {
		return true
	}
	if i > 50 && (i%50) == 0 {
		return true
	}

	return false
}

func (a *alerts) add(alert *pb.Alert) {
	a.Lock()
	if len(a.m) > 20 {
		log.WithFields(log.Fields{
			"client":      alert.Issue.Host,
			"alert":       alert.String(),
			"occurrences": alert.Occurrences,
		}).Debugln("issues map is greater than 20", len(a.m))
	}
	a.m[generateMapKey(alert.Issue)] = alert
	a.Unlock()
}

// count increases the number of occurrences and returns it
//
//	it should only be called in alert(), ensuring the occurrences always increase
//	TimeLast is updated as well, to track stale alerts
func (a *alerts) count(issue *pb.Issue) int64 {
	a.Lock()
	v := a.m[generateMapKey(issue)]
	v.Occurrences = v.Occurrences + 1
	v.TimeLast = time.Now().Unix()
	a.Unlock()
	return v.Occurrences
}

func (a *alerts) exists(issue *pb.Issue) bool {
	a.Lock()
	_, alertExists := a.m[generateMapKey(issue)]
	a.Unlock()
	return alertExists
}

func (a *alerts) get(issue *pb.Issue) *pb.Alert {
	a.Lock()
	theAlert, alertExists := a.m[generateMapKey(issue)]
	if alertExists {
		a.Unlock()
		return theAlert
	}

	a.Unlock()
	return nil
}

func (a *alerts) mute(issueID string) {
	a.Lock()
	v := a.m[issueID]
	v.Muted = true
	a.Unlock()
}

func (a *alerts) muteAll(allAlerts *alerts) {
	a.Lock()
	for _, v := range a.m {
		v.Muted = true
	}
	a.Unlock()
}

func (a *alerts) isMuted(issue *pb.Issue) bool {
	var isIt bool
	a.Lock()
	v := a.m[generateMapKey(issue)]
	isIt = v.Muted
	a.Unlock()
	return isIt
}

// expire expires issues that have been stale for 1 hour
func (a *alerts) expire(issue *pb.Issue) {
	a.Lock()
	issueID := generateMapKey(issue)
	v, alertExists := a.m[issueID]

	if alertExists {

		lastOccurrence := time.Since(time.Unix(v.TimeLast, 0))

		if lastOccurrence.Hours() > 1.00 {
			log.WithFields(log.Fields{
				"issue": v.Issue.Title,
				"host":  v.Issue.Host,
			}).Infoln("Expiring alert")

			delete(a.m, issueID)
		}

	}

	a.Unlock()
}

/*
func (a *alerts) exists(client string, alert gorram.Alert, interval int64) (resend, exists bool) {
	a.Lock()
	alertHash := alert.Issue.Title + alert.Issue.Message
	clientAlerts := a.m[client]
	log.Println(len(clientAlerts))
	for i, v := range clientAlerts {
		if alertHash == v.Issue.Title+v.Issue.Message {
			// Increase Occurrences counter
			v.Occurrences = v.Occurrences + 1

			log.Println(v.String())

			// Send the first 2 alerts
			if v.Occurrences < 5 {
				log.Println("Alert is not stale yet.", v.Occurrences)
				a.Unlock()
				return true, false
			}

			if v.Occurrences > 25 {
				log.Println("Alert is stale! Deleting alert from map...")
				//log.Println(len(a.m[client]))
				a.m[client][i] = a.m[client][len(a.m[client])-1]
				a.m[client] = a.m[client][:len(a.m[client])-1]
				//a.m[client] = append(a.m[client][:i], a.m[client][i+1:]...)
				//log.Println(len(a.m[client]))
				a.Unlock()
				return false, false
			}
			a.Unlock()
			return false, true
		}
	}
	a.Unlock()
	return false, false
}
*/

// MapKey should consist of host+title, allowing message to continue updating
// This allows disk space and other alerts to change without unmuting
func generateMapKey(i *pb.Issue) string {
	return base64.RawURLEncoding.EncodeToString([]byte(i.Host + i.Title))
}
