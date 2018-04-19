package checks

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	pb "jba.io/go/gorram/proto"
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
	defer resp.Body.Close()

	if resp.StatusCode == 200 && g.Cfg.ExpectedBody != "" {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return &checkData{
				issue: &pb.Issue{
					Title:         "Get URL",
					Message:       fmt.Sprintf("%v error reading body: %v", g.Cfg.Url, err),
					TimeSubmitted: time.Now().Unix(),
				},
				ok: false,
			}
		}
		if !bytes.Equal(body, []byte(g.Cfg.ExpectedBody)) {
			return &checkData{
				issue: &pb.Issue{
					Title:         "Get URL",
					Message:       fmt.Sprintf("%v body content is unexpected.", g.Cfg.Url),
					TimeSubmitted: time.Now().Unix(),
				},
				ok: false,
			}
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
	return &checkData{
		ok: true,
	}
}
