package main

import (
	pb "git.sr.ht/~aqtrans/gorram/proto"
	"github.com/go-openapi/strfmt"
	"github.com/prometheus/alertmanager/api/v2/client"
	"github.com/prometheus/alertmanager/api/v2/client/alert"
	"github.com/prometheus/alertmanager/api/v2/models"
	log "github.com/sirupsen/logrus"
)

func (s *gorramServer) addToAlertManager(issue *pb.Issue) {
	l := make(map[string]string)
	l["host"] = issue.Host
	l["check"] = issue.Title

	annotations := make(map[string]string)
	annotations["summary"] = issue.Message

	a := &models.PostableAlert{
		Alert: models.Alert{
			GeneratorURL: strfmt.URI(s.cfg.AlertManagerURL),
			Labels:       l,
		},
		Annotations: annotations,
	}
	c := client.NewHTTPClientWithConfig(nil, &client.TransportConfig{
		Host:     "localhost:9093",
		BasePath: "/api/v2",
		Schemes:  []string{"http"},
	})
	al := alert.NewPostAlertsParams().WithAlerts(models.PostableAlerts{a})
	ok, err := c.Alert.PostAlerts(al)
	log.Println(ok.Error())

	if err != nil {
		log.Println("error submitting to alert manager:", err)
	}
}
