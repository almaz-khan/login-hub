package main

// A Telegram message to the owner (access.json «notify») when someone tries to open an app they
// aren't allowed in, from the bot that runs the login (TG_BOT_TOKEN; the owner has to press Start
// in the bot once). At most one message an hour per person and app. Sending happens in the
// background, so a slow or failing Telegram never holds up the page.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"time"
)

const notifyEvery = time.Hour

func (a *app) notifyDenied(who sessionData, c *client) {
	if a.cfg.BotToken == "" || a.access.Notify == "" {
		return
	}
	key := who.ID + " " + c.ID
	now := a.now()
	a.notifyMu.Lock()
	if last, ok := a.notified[key]; ok && now.Sub(last) < notifyEvery {
		a.notifyMu.Unlock()
		return
	}
	for k, t := range a.notified { // forget what was reported more than an hour ago
		if now.Sub(t) >= notifyEvery {
			delete(a.notified, k)
		}
	}
	a.notified[key] = now
	a.notifyMu.Unlock()

	// HTML so the name links to the profile; everything from Telegram is escaped
	label := fmt.Sprintf(`<a href="tg://user?id=%s">%s</a>`, who.ID, html.EscapeString(or(who.Name, "Без имени")))
	text := "🚫 Нет доступа к «" + html.EscapeString(c.Name) + "»\n" + label
	if who.Username != "" {
		text += " (@" + html.EscapeString(who.Username) + ")"
	}
	text += "\nTelegram id: " + who.ID

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.send(text)
	}()
}

// waitNotify waits for the messages still sending, at most until ctx ends
func (a *app) waitNotify(ctx context.Context) {
	done := make(chan struct{})
	go func() { a.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		a.log.Printf("notify: gave up on messages still sending")
	}
}

func (a *app) send(text string) {
	body, _ := json.Marshal(map[string]any{"chat_id": a.access.Notify, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, a.botAPI+"/bot"+a.cfg.BotToken+"/sendMessage", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		// the request URL carries the bot token: log only the underlying error
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		a.log.Printf("notify failed: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		var r struct {
			Description string `json:"description"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = json.Unmarshal(b, &r)
		a.log.Printf("notify failed: telegram %d %s", resp.StatusCode, r.Description)
		return
	}
	a.log.Printf("notify: sent")
}
