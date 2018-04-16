package checks

import (
	"fmt"
	pb "jba.io/go/gorram/proto"
	"net/http"
	"time"
)

type GetURL struct {
	Cfg pb.GetURL
}

func (g GetURL) doCheck() *checkData {

	resp, err := http.Get(g.Cfg.Url)
	if err != nil {
		return &checkData{
			issue: &pb.Issue{
				Title:         "Get URL",
				Message:       fmt.Sprintf("Error checking %v: %v.", g.Cfg.Url, err),
				TimeSubmitted: time.Now().Unix(),
			},
			ok: false,
		}
	}
	if resp.StatusCode != 200 {
		return &checkData{
			issue: &pb.Issue{
				Title:         "Get URL",
				Message:       fmt.Sprintf("%v did not respond with a 200: %v.", g.Cfg.Url, resp.StatusCode),
				TimeSubmitted: time.Now().Unix(),
			},
			ok: false,
		}
	}
	return nil
}
