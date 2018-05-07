package checks

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"

	pb "jba.io/go/gorram/proto"
)

type GetURL struct {
	Cfg pb.GetURL
}

func (g GetURL) doCheck() string {

	resp, err := http.Get(g.Cfg.Url)
	if err != nil {
		return fmt.Sprintf("Error checking %v: %v.", g.Cfg.Url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 && g.Cfg.ExpectedBody != "" {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Sprintf("%v error reading body: %v", g.Cfg.Url, err)
		}
		if !bytes.Equal(body, []byte(g.Cfg.ExpectedBody)) {
			return fmt.Sprintf("%v body content is unexpected.", g.Cfg.Url)
		}
	}

	if resp.StatusCode != 200 {
		return fmt.Sprintf("%v did not respond with a 200: %v.", g.Cfg.Url, resp.StatusCode)
	}
	return ""
}
