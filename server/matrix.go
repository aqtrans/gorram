// Copyright (C) 2017 Tulir Asokan
// Copyright (C) 2018-2020 Luca Weiss
// Copyright (C) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"context"

	pb "git.jba.io/go/gorram/proto"
	"github.com/rs/zerolog/log"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"
)

func (s *gorramServer) setupMatrixClient() {
	var homeserver = &s.cfg.Matrix.Homeserver
	var username = &s.cfg.Matrix.Username
	var password = &s.cfg.Matrix.Password
	//var database = &s.cfg.Matrix.SqliteDB
	//var database = &s.cfg.Matrix.SqliteDB
	//var debug = &s.cfg.Debug

	if *username == "" || *password == "" || *homeserver == "" {
		log.Fatal().Msg("matrix config is missing")
	}

	client, err := mautrix.NewClient(*homeserver, "", "")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	//client.Log = log

	var lastRoomID id.RoomID

	syncer := client.Syncer.(*mautrix.DefaultSyncer)

	/*
		syncer.OnEventType(event.EventMessage, func(ctx context.Context, evt *event.Event) {
			if client.UserID != evt.Sender {
				lastRoomID = evt.RoomID
				log.Info().
					Str("sender", evt.Sender.String()).
					Str("type", evt.Type.String()).
					Str("id", evt.ID.String()).
					Str("body", evt.Content.AsMessage().Body).
					Msg("Received message")
			}
		})
	*/

	syncer.OnEventType(event.StateMember, func(ctx context.Context, evt *event.Event) {
		if evt.GetStateKey() == client.UserID.String() && evt.Content.AsMember().Membership == event.MembershipInvite {
			_, err := client.JoinRoomByID(ctx, evt.RoomID)
			if err == nil {
				lastRoomID = evt.RoomID
				log.Info().
					Str("room_id", evt.RoomID.String()).
					Str("inviter", evt.Sender.String()).
					Msg("Joined room after invite")
			} else {
				log.Error().Err(err).
					Str("room_id", evt.RoomID.String()).
					Str("inviter", evt.Sender.String()).
					Msg("Failed to join room after invite")
			}
		}
	})

	cryptoHelper, err := cryptohelper.NewCryptoHelper(client, []byte("meow"), "database.db")
	if err != nil {
		log.Fatal().Msg("error opening sqlitedb: " + err.Error())
	}

	// You can also store the user/device IDs and access token and put them in the client beforehand instead of using LoginAs.
	//client.UserID = "..."
	//client.DeviceID = "..."
	//client.AccessToken = "..."
	// You don't need to set a device ID in LoginAs because the crypto helper will set it for you if necessary.
	cryptoHelper.LoginAs = &mautrix.ReqLogin{
		Type:       mautrix.AuthTypePassword,
		Identifier: mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: *username},
		Password:   *password,
	}
	// If you want to use multiple clients with the same DB, you should set a distinct database account ID for each one.
	//cryptoHelper.DBAccountID = ""
	err = cryptoHelper.Init(context.TODO())
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	// Set the client crypto helper in order to automatically encrypt outgoing messages
	client.Crypto = cryptoHelper

	log.Info().Msg("Now running")

	// Try to silence alerts
	syncer.OnEventType(event.EventMessage, func(ctx context.Context, evt *event.Event) {
		if evt.Sender == client.UserID {
			return
		}
		lastRoomID = evt.RoomID
		log.Info().
			Str("sender", evt.Sender.String()).
			Str("type", evt.Type.String()).
			Str("id", evt.ID.String()).
			Str("body", evt.Content.AsMessage().Body).
			Msg("Received message")

		// Silence all events if told to
		if evt.Content.AsMessage().Body == "Silence all" {
			s.alertsMap.muteAll(&s.alertsMap)
			_, err := client.SendText(context.TODO(), lastRoomID, "Silencing all alerts for 6 hours")
			if err != nil {
				log.Error().Err(err).Msg("Failed to send silence event")
			}
		}

		/* TODO: Figure out how to use replies to mute; currently unable to figure out how to fetch
		if evt.Content.AsMessage().OptionalGetRelatesTo() != nil {
			log.Print("Thread reply detected")
			// Get thread parent
			oldEventID := evt.Content.AsMessage().GetRelatesTo().GetThreadParent()
			oldResp, err := client.GetEvent(context.TODO(), evt.RoomID, oldEventID)
			if err != nil {
				log.Error().Err(err).Msg("error fetching original reply")
			}
			issueID, found := strings.CutPrefix(oldResp.Content.AsMessage().Body, "IssueID:")
			if !found {
				log.Info().Msg("alert ID not found:" + issueID)
			}
			s.alertsMap.mute(issueID)
			log.Info().Msg("alert actually muted!")

			_, err = client.SendText(context.TODO(), lastRoomID, "Silencing alert #"+issueID)
			if err != nil {
				log.Error().Err(err).Msg("Failed to send silence event")
			}
		}
		*/

	})

	resp, err := client.SendText(context.TODO(), lastRoomID, "Hello!")
	if err != nil {
		log.Error().Err(err).Msg("Failed to send hello event")
	} else {
		log.Info().Str("event_id", resp.EventID.String()).Msg("Event sent")
	}

	go func() {
		err = client.Sync()
		if err != nil {
			log.Print(err)
			err = cryptoHelper.Close()
			if err != nil {
				log.Error().Err(err).Msg("Error closing database")
			}
			return
		}
	}()

	s.matrixbot = client

}

func (s *gorramServer) sendToMatrix(issue *pb.Issue) error {

	roomID := id.RoomID("!TKWpjUwOWJmHVsPyBc:matrix.org")

	//msg := issue.Host + " - " + issue.Title + "\n" + issue.Message

	msg := format.RenderMarkdown("IssueID:"+generateMapKey(issue)+" #"+issue.Host+"  ##"+issue.Title+"  "+issue.Message, true, false)

	resp, err := s.matrixbot.SendMessageEvent(context.TODO(), roomID, event.EventMessage, msg)
	if err != nil {
		log.Error().Msg("Failed to send event")
		return err
	} else {
		log.Print("event_id", resp.EventID.String()+"vent sent")
	}
	return nil
}
