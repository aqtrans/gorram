package checks

import (
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"time"

	pb "jba.io/go/gorram/proto"
)

type LoadAvg struct {
	MaxLoad float64
}

func (l LoadAvg) doCheck() *checkData {
	loadAvgRaw, err := ioutil.ReadFile("/proc/loadavg")
	if err != nil {
		log.Println("Error reading load average:", err)
		return nil
	}
	loadAvgs := strings.Fields(string(loadAvgRaw))

	for k, v := range loadAvgs {
		if k > 2 {
			break
		}
		loadAvg, err := strconv.ParseFloat(v, 64)
		if err != nil {
			log.Println("Error parsing loadavg:", err)
			return nil
		}
		if loadAvg >= l.MaxLoad {

			return &checkData{
				issues: []*pb.Issue{
					&pb.Issue{
						Title:         "Load Average",
						Message:       fmt.Sprintf("Load average is greater than %f, %f", l.MaxLoad, loadAvg),
						TimeSubmitted: time.Now().Unix(),
					},
				},
				ok: false,
			}
		}
	}

	return &checkData{
		issues: nil,
		ok:     true,
	}
}
