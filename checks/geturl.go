package checks

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"

	pb "git.jba.io/go/gorram/proto"
)

type getURL struct {
	Cfg []*pb.Config_GetURL
}

func init() {
	theChecks = append(theChecks, &getURL{})
}

func (g getURL) Title() string {
	return "GetUrl"
}

func (g *getURL) configure(cfg *pb.Config) error {
	if cfg.GetGetUrl() == nil {
		return errEmptyConfig
	}
	g.Cfg = cfg.GetGetUrl()
	return nil
}

func (g getURL) doCheck(issues *[]pb.Issue) {

	for _, urlCheck := range g.Cfg {

		resp, err := http.Get(urlCheck.Url)
		if err != nil {
			addIssue(issues, g.Title(), fmt.Sprintf("Error checking %v: %v.", urlCheck.Url, err))
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 && urlCheck.ExpectedBody != "" {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				addIssue(issues, g.Title(), fmt.Sprintf("%v error reading body: %v", urlCheck.Url, err))
				continue
			}
			if !bytes.Equal(body, []byte(urlCheck.ExpectedBody)) {
				addIssue(issues, g.Title(), fmt.Sprintf("%v body content is unexpected.", urlCheck.Url))
				continue
			}
		}

		if resp.StatusCode != 200 {
			addIssue(issues, g.Title(), fmt.Sprintf("%v did not respond with a 200: %v.", urlCheck.Url, resp.StatusCode))
			continue
		}
	}
}
