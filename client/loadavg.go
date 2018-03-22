package main

import (
	"fmt"
	"io/ioutil"
	pb "jba.io/go/gorram/proto"
	"log"
	"strconv"
	"strings"
	"time"
)

type loadavg struct {
	maxLoad float64
}

func (l loadavg) doCheck() *checkData {
	loadAvgRaw, err := ioutil.ReadFile("/proc/loadavg")
	if err != nil {
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
		if loadAvg >= l.maxLoad {
			log.Printf("Load average is greater than %f, %f", l.maxLoad, loadAvg)

			return &checkData{
				issue: &pb.Issue{
					Message:       fmt.Sprintf("Load average is greater than %f, %f", l.maxLoad, loadAvg),
					TimeSubmitted: time.Now().Unix(),
				},
				ok: false,
			}
		}
	}
	return &checkData{
		issue: nil,
		ok:    true,
	}
}
