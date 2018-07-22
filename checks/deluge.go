package checks

//USAGE: ./check-deluge -n [max number of torrents] -p [password for Deluge web ui]
//This is a replacement for my bash-powered Deluge Sensu check, which was just using `deluge-console|grep`
//It takes advantage of the Deluge WebUI JSON API
//To keep things simple, it sets a bool variable to true, which is finally what determines the exit status of the program, telling Sensu what to do

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"time"
	//"strings"

	//"github.com/smallnest/goreq"
	pb "jba.io/go/gorram/proto"
)

type DelugeCheck struct {
	Cfg pb.Deluge
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

/*
func (d DelugeCheck) post(c *http.Client, req *delugeRequest, resp interface{}) {
	reqJSON, err := json.Marshal(req)
	if err != nil {
		log.Fatalln("error encoding request to JSON:", err)
	}
	r, err := c.Post(d.Cfg.Url, "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		log.Fatalln("error sending request to Deluge:", err)
	}
	if r.Body != nil {
		err := json.NewDecoder(r.Body).Decode(resp)
		if err != nil {
			log.Fatalln("error decoding request to JSON:", err)
		}
	}
}
*/

func (d DelugeCheck) title() string {
	return "Deluge"
}

func (d DelugeCheck) doCheck() string {

	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Sprintf("Error creating cookiejar: %v", err)
	}

	client := &http.Client{
		Jar:     cookieJar,
		Timeout: 5 * time.Second,
	}

	// auth.login: Login and set the cookie
	/*
		var loginJSON delugeResponse
		_, _, reqErr := goreq.New().Post(d.Cfg.Url).SendStruct(&delugeRequest{
			ID:     "1",
			Method: "auth.login",
			Params: []string{d.Cfg.Password},
		}).BindBody(&loginJSON).SetClient(client).End()

		if reqErr != nil {
			fmt.Println(reqErr)
			os.Exit(2)
		}
	*/
	var loginJSON delugeResponse
	/*
		d.post(client, &delugeRequest{
			ID:     "1",
			Method: "auth.login",
			Params: []string{d.Cfg.Password},
		}, &loginJSON)
	*/

	reqJSON, err := json.Marshal(&delugeRequest{
		ID:     "1",
		Method: "auth.login",
		Params: []string{d.Cfg.Password},
	})
	if err != nil {
		return fmt.Sprint("Error encoding request to JSON:", err)
	}
	r, err := client.Post(d.Cfg.Url, "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		return fmt.Sprint("Error sending request to Deluge:", err)
	}
	if r.Body != nil {
		err := json.NewDecoder(r.Body).Decode(&loginJSON)
		if err != nil {
			return fmt.Sprint("Error decoding request to JSON:", err)
		}
	}

	if !loginJSON.Result {
		return "Error logging into Deluge. Check password."
	}

	// auth.check_session: Should definitely return true if the cookie set above is set correctly
	/*
		var loginOkayJSON delugeResponse
		_, _, reqErr = goreq.New().Post(d.Cfg.Url).SendStruct(&delugeRequest{
			ID:     "1",
			Method: "auth.check_session",
			Params: []string{},
		}).BindBody(&loginOkayJSON).SetClient(client).End()

		if reqErr != nil {
			fmt.Println(reqErr)
			os.Exit(2)
		}
	*/
	var loginOkayJSON delugeResponse
	/*
		d.post(client, &delugeRequest{
			ID:     "1",
			Method: "auth.check_session",
			Params: []string{},
		}, &loginOkayJSON)
	*/

	reqJSON2, err := json.Marshal(&delugeRequest{
		ID:     "1",
		Method: "auth.check_session",
		Params: []string{},
	})
	if err != nil {
		return fmt.Sprint("Error encoding request to JSON:", err)
	}
	r2, err := client.Post(d.Cfg.Url, "application/json", bytes.NewBuffer(reqJSON2))
	if err != nil {
		return fmt.Sprint("Error sending request to Deluge:", err)
	}
	if r2.Body != nil {
		err := json.NewDecoder(r2.Body).Decode(&loginOkayJSON)
		if err != nil {
			return fmt.Sprint("Error decoding request to JSON:", err)
		}
	}

	if !loginOkayJSON.Result {
		return "Error logging into Deluge. Check password."
	}

	// web.update_ui: Try and retrieve data
	var updateResp updateJSON
	/*
		resp, _, reqErr := goreq.New().Post(d.Cfg.Url).SendStruct(&delugeRequest{
			ID:     "1",
			Method: "web.update_ui",
			Params: []string{"name", "time_added"},
		}).BindBody(&updateResp).SetClient(client).End()

		if reqErr != nil {
			fmt.Println(reqErr)
			os.Exit(2)
		}
	*/
	/*
		d.post(client, &delugeRequest{
			ID:     "1",
			Method: "web.update_ui",
			Params: []string{"name", "time_added"},
		}, &updateResp)
	*/

	reqJSON3, err := json.Marshal(&delugeRequest{
		ID:     "1",
		Method: "web.update_ui",
		Params: []string{"name", "time_added"},
	})
	if err != nil {
		return fmt.Sprint("Error encoding request to JSON:", err)
	}
	r3, err := client.Post(d.Cfg.Url, "application/json", bytes.NewBuffer(reqJSON3))
	if err != nil {
		return fmt.Sprint("Error sending request to Deluge:", err)
	}
	if r3.Body != nil {
		err := json.NewDecoder(r3.Body).Decode(&updateResp)
		if err != nil {
			return fmt.Sprint("Error decoding request to JSON:", err)
		}
	}

	/*
		// Check that this returned 200
		if resp.StatusCode != 200 {
			fmt.Println("web.update_ui did not return 200:", resp.Status)
			os.Exit(2)
		}
	*/

	if len(updateResp.Result.Filters.State) == 0 {
		return "Error: Deluge web-ui likely waiting to connect to a host. Visit the web-ui manually."
	}

	//fmt.Println(updateResp.Result.TorrentsJson)

	// updateres.Result.Filters spits out [[All 941] [Downloading 1] [Seeding 794] [Active 1] [Paused 146] [Queued 0] [Checking 0] [Error 0]]
	// An array of arrays, handy!
	downloading := updateResp.Result.Filters.State[1]
	dlcnt := int64(downloading[1].(float64))
	checking := updateResp.Result.Filters.State[6]
	chkcnt := int64(checking[1].(float64))
	erroring := updateResp.Result.Filters.State[7]
	errcnt := int64(erroring[1].(float64))

	//fmt.Println(dlcnt)
	//fmt.Println(chkcnt)
	//fmt.Println(errcnt)
	if dlcnt > d.Cfg.MaxTorrents {
		isBad = true
		badMsg = strconv.FormatInt(dlcnt, 10) + " downloading torrents is too many."

	}
	if chkcnt > d.Cfg.MaxTorrents {
		isBad = true
		badMsg = strconv.FormatInt(chkcnt, 10) + " checking torrents is too many."
	}
	if errcnt > d.Cfg.MaxTorrents {
		isBad = true
		badMsg = strconv.FormatInt(errcnt, 10) + " errored torrents is too many."
	}
	//fmt.Println(isBad)
	//fmt.Println(badMsg)

	if isBad {
		return badMsg
	}

	return ""

}
