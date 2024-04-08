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
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	pb "git.jba.io/go/gorram/proto"
	"github.com/chzyer/readline"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"go.mau.fi/util/exzerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func (s *gorramServer) sendToMatrix(issue *pb.Issue) error {
	var homeserver = &s.cfg.Matrix.Homeserver
	var username = &s.cfg.Matrix.Username
	var password = &s.cfg.Matrix.Password
	var database = &s.cfg.Matrix.SqliteDB
	var debug = &s.cfg.Debug

	if *username == "" || *password == "" || *homeserver == "" {
		_, _ = fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		return errors.New("Matrix config is missing.")
	}

	client, err := mautrix.NewClient(*homeserver, "", "")
	if err != nil {
		return err
	}
	rl, err := readline.New("[no room]> ")
	if err != nil {
		return err
	}
	defer rl.Close()
	log := zerolog.New(zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
		w.Out = rl.Stdout()
		w.TimeFormat = time.Stamp
	})).With().Timestamp().Logger()
	if !*debug {
		log = log.Level(zerolog.InfoLevel)
	}
	exzerolog.SetupDefaults(&log)
	client.Log = log

	var lastRoomID id.RoomID

	syncer := client.Syncer.(*mautrix.DefaultSyncer)
	syncer.OnEventType(event.EventMessage, func(ctx context.Context, evt *event.Event) {
		lastRoomID = evt.RoomID
		rl.SetPrompt(fmt.Sprintf("%s> ", lastRoomID))
		log.Info().
			Str("sender", evt.Sender.String()).
			Str("type", evt.Type.String()).
			Str("id", evt.ID.String()).
			Str("body", evt.Content.AsMessage().Body).
			Msg("Received message")
	})
	syncer.OnEventType(event.StateMember, func(ctx context.Context, evt *event.Event) {
		if evt.GetStateKey() == client.UserID.String() && evt.Content.AsMember().Membership == event.MembershipInvite {
			_, err := client.JoinRoomByID(ctx, evt.RoomID)
			if err == nil {
				lastRoomID = evt.RoomID
				rl.SetPrompt(fmt.Sprintf("%s> ", lastRoomID))
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

	cryptoHelper, err := cryptohelper.NewCryptoHelper(client, []byte("meow"), *database)
	if err != nil {
		return err
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
		return err
	}
	// Set the client crypto helper in order to automatically encrypt outgoing messages
	client.Crypto = cryptoHelper

	log.Info().Msg("Now running")
	syncCtx, cancelSync := context.WithCancel(context.Background())
	var syncStopWait sync.WaitGroup
	syncStopWait.Add(1)

	go func() {
		err = client.SyncWithContext(syncCtx)
		defer syncStopWait.Done()
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	line := issue.Host + " - " + issue.Title + "\n" + issue.Message

	for {
		if lastRoomID == "" {
			log.Error().Msg("Wait for an incoming message before sending messages")
			continue
		}

		// Try to silence alerts
		syncer.OnEventType(event.EventReaction, func(ctx context.Context, evt *event.Event) {
			lastRoomID = evt.RoomID
			rl.SetPrompt(fmt.Sprintf("%s> ", lastRoomID))
			eventID := evt.Content.AsReaction().RelatesTo.EventID
			log.Info().
				Str("sender", evt.Sender.String()).
				Str("type", evt.Type.String()).
				Str("id", evt.ID.String()).
				Str("body", evt.Content.AsMessage().Body).
				Msg("Received message")
			_, err := client.SendText(context.TODO(), lastRoomID, "Silencing alert #"+eventID.String())
			if err != nil {
				log.Error().Err(err).Msg("Failed to send event")
			}

		})
		resp, err := client.SendText(context.TODO(), lastRoomID, line)
		if err != nil {
			log.Error().Err(err).Msg("Failed to send event")
		} else {
			log.Info().Str("event_id", resp.EventID.String()).Msg("Event sent")
		}
	}
	cancelSync()
	syncStopWait.Wait()
	err = cryptoHelper.Close()
	if err != nil {
		log.Error().Err(err).Msg("Error closing database")
	}
	return nil
}
