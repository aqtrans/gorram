package main

import (
	"time"

	pb "git.jba.io/go/gorram/proto"
	log "github.com/sirupsen/logrus"
)

func (c *clients) add(client *pb.Client) {
	c.Lock()
	c.m.Clients[client.Name] = client
	c.Unlock()
}

func (c *clients) exists(clientName string) bool {
	c.Lock()
	_, clientExists := c.m.Clients[clientName]
	c.Unlock()
	return clientExists
}

func (c *clients) get(clientName string) *pb.Client {
	c.Lock()
	theClient, clientExists := c.m.Clients[clientName]
	if clientExists {
		c.Unlock()
		return theClient
	}

	c.Unlock()
	return nil
}

func (c *clients) delete(clientName string) {
	c.Lock()
	_, clientExists := c.m.Clients[clientName]
	if clientExists {
		c.Unlock()
		return
	}
	delete(c.m.Clients, clientName)

	c.Unlock()
}

func (c *clients) updatePingTime(clientName string) {
	c.Lock()
	_, clientExists := c.m.Clients[clientName]
	if clientExists {
		c.m.Clients[clientName].LastPingTime = time.Now().Unix()

		c.Unlock()
		return
	}
	c.Unlock()
}

func (c *clients) expired(clientName string, pingInterval int64) bool {
	c.Lock()
	_, clientExists := c.m.Clients[clientName]
	if clientExists {
		now := time.Now()
		lastPingTime := time.Unix(c.m.Clients[clientName].LastPingTime, 0)
		// If client hasn't pinged in pingInterval * 2, consider it expired
		log.Debugln(clientName, "difference between now and last ping time:", now.Sub(lastPingTime).String())
		if now.Sub(lastPingTime).Seconds() > float64(pingInterval*2) {
			c.Unlock()
			return true
		}
		c.Unlock()
		return false
	}
	c.Unlock()
	return false
}
