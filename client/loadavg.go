package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"time"

	gorram "jba.io/go/gorram/proto"
)

type loadavg struct {
}

func (loadavg) doCheck(cfg *config) *gorram.Issue {
	loadAvgRaw, err := ioutil.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}
	loadAvgs := strings.Fields(string(loadAvgRaw))
	/*
		loadAvg1, err := strconv.ParseFloat(loadAvgs[0], 64)
		if err != nil {
			return nil
		}
		loadAvg5, err := strconv.ParseFloat(loadAvgs[1], 64)
		if err != nil {
			return nil
		}
		loadAvg15, err := strconv.ParseFloat(loadAvgs[2], 64)
		if err != nil {
			return nil
		}
	*/

	for k, v := range loadAvgs {
		if k > 3 {
			break
		}
		loadAvg, err := strconv.ParseFloat(v, 64)
		if err != nil {
			log.Println("Error parsing loadavg:", err)
			return nil
		}
		if loadAvg >= cfg.loadavg {
			log.Printf("Load average is greater than %f, %f", cfg.loadavg, loadAvg)
			return &gorram.Issue{
				Message:       fmt.Sprintf("Load average is greater than %f, %f", cfg.loadavg, loadAvg),
				TimeSubmitted: time.Now().Unix(),
			}
		}
	}
	return nil
}
