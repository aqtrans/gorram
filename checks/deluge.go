package checks

//USAGE: ./check-deluge -n [max number of torrents] -p [password for Deluge web ui]
//This is a replacement for my bash-powered Deluge Sensu check, which was just using `deluge-console|grep`
//It takes advantage of the Deluge WebUI JSON API
//To keep things simple, it sets a bool variable to true, which is finally what determines the exit status of the program, telling Sensu what to do

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strconv"
	"time"
	//"strings"

	"github.com/smallnest/goreq"
	pb "jba.io/go/gorram/proto"
)

type DelugeCheck struct {
	URL         string
	Password    string
	MaxTorrents int
}

var (
	isBad  bool
	badMsg string
)

type delugeRequest struct {
	ID     string      `json:"id"`
	Method string      `json:"method"`
	Params interface{} `json:"params"`
}

type delugeResponse struct {
	ID     string `json:"id"`
	Result bool   `json:"result"`
	Error  string `json:"error"`
}

type torrents struct {
	TimeAdded json.Number `json:"time_added"`
	Name      string      `json:"name"`
}

type torrentsJSON map[string]torrents

type updateJSON struct {
	ID     string `json:"id"`
	Result struct {
		Stats struct {
			UploadProtocolRate     float64 `json:"upload_protocol_rate"`
			MaxUpload              float64 `json:"max_upload"`
			DownloadProtocolRate   float64 `json:"download_protocol_rate"`
			DownloadRate           float64 `json:"download_rate"`
			HasIncomingConnections bool    `json:"has_incoming_connections"`
			NumConnections         float64 `json:"num_connections"`
			MaxDownload            float64 `json:"max_download"`
			UploadRate             float64 `json:"upload_rate"`
			DhtNodes               float64 `json:"dht_nodes"`
			FreeSpace              int64   `json:"free_space"`
			MaxNumConnections      float64 `json:"max_num_connections"`
		} `json:"stats"`
		Connected    bool `json:"connected"`
		torrentsJSON `json:"torrents"`
		Filters      struct {
			State       [][]interface{} `json:"state"`
			TrackerHost [][]interface{} `json:"tracker_host"`
			Label       [][]interface{} `json:"label"`
		} `json:"filters"`
	} `json:"result"`
	Error interface{} `json:"error"`
}

func (d DelugeCheck) doCheck() *checkData {

	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}

	client := &http.Client{
		Jar:     cookieJar,
		Timeout: 5 * time.Second,
	}

	// auth.login: Login and set the cookie
	var loginJSON delugeResponse
	_, _, reqErr := goreq.New().Post(d.URL).SendStruct(&delugeRequest{
		ID:     "1",
		Method: "auth.login",
		Params: []string{d.Password},
	}).BindBody(&loginJSON).SetClient(client).End()

	if reqErr != nil {
		fmt.Println(reqErr)
		os.Exit(2)
	}
	if !loginJSON.Result {
		fmt.Println("Error logging into Deluge. Check password.")
		os.Exit(2)
	}

	// auth.check_session: Should definitely return true if the cookie set above is set correctly
	var loginOkayJSON delugeResponse
	_, _, reqErr = goreq.New().Post(d.URL).SendStruct(&delugeRequest{
		ID:     "1",
		Method: "auth.check_session",
		Params: []string{},
	}).BindBody(&loginOkayJSON).SetClient(client).End()

	if reqErr != nil {
		fmt.Println(reqErr)
		os.Exit(2)
	}
	if !loginOkayJSON.Result {
		fmt.Println("Error logging into Deluge. Check password.")
		os.Exit(2)
	}

	// web.update_ui: Try and retrieve data
	var updateResp updateJSON
	resp, _, reqErr := goreq.New().Post(d.URL).SendStruct(&delugeRequest{
		ID:     "1",
		Method: "web.update_ui",
		Params: []string{"name", "time_added"},
	}).BindBody(&updateResp).SetClient(client).End()

	if reqErr != nil {
		fmt.Println(reqErr)
		os.Exit(2)
	}
	// Check that this returned 200
	if resp.StatusCode != 200 {
		fmt.Println("web.update_ui did not return 200:", resp.Status)
		os.Exit(2)
	}

	if len(updateResp.Result.Filters.State) == 0 {
		fmt.Println("Error: Deluge web-ui likely waiting to connect to a host. Visit the web-ui manually.")
		os.Exit(2)
	}

	//fmt.Println(updateResp.Result.TorrentsJson)

	// updateres.Result.Filters spits out [[All 941] [Downloading 1] [Seeding 794] [Active 1] [Paused 146] [Queued 0] [Checking 0] [Error 0]]
	// An array of arrays, handy!
	downloading := updateResp.Result.Filters.State[1]
	dlcnt := int(downloading[1].(float64))
	checking := updateResp.Result.Filters.State[6]
	chkcnt := int(checking[1].(float64))
	erroring := updateResp.Result.Filters.State[7]
	errcnt := int(erroring[1].(float64))

	//fmt.Println(dlcnt)
	//fmt.Println(chkcnt)
	//fmt.Println(errcnt)
	if dlcnt > d.MaxTorrents {
		isBad = true
		badMsg = strconv.Itoa(dlcnt) + " downloading torrents is too many."
	}
	if chkcnt > d.MaxTorrents {
		isBad = true
		badMsg = strconv.Itoa(chkcnt) + " checking torrents is too many."
	}
	if errcnt > d.MaxTorrents {
		isBad = true
		badMsg = strconv.Itoa(errcnt) + " errored torrents is too many."
	}
	//fmt.Println(isBad)
	//fmt.Println(badMsg)

	if isBad {
		return &checkData{
			issues: []*pb.Issue{
				&pb.Issue{
					Title:         "Deluge",
					Message:       badMsg,
					TimeSubmitted: time.Now().Unix(),
				},
			},
			ok: false,
		}
	}

	return &checkData{
		issues: nil,
		ok:     true,
	}

}
