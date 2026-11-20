package disclosuredata

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"

	p "privacy-proxy/internal/disclosurepolicy"
)

type eventsPageDTO struct {
	Version    uint8      `json:"v"`
	Population string     `json:"population"`
	Items      []EventDTO `json:"items"`
	NextCursor *string    `json:"nextCursor"`
}

func (c factContext) validateEvents(f Facts, after *Position, checkInitial bool) error {
	if !c.nativeEvents || f.Events == nil || len(f.Events) > int(c.scope.Query.limit) {
		return ErrUnavailable
	}
	var previous *EventsPosition
	pending := checkInitial && after != nil && after.Events.Mode == "pending"
	if pending && (f.End || f.Next == nil || f.Next.Events == nil || f.Next.Events.Parent != after.Events.Parent) {
		return ErrUnavailable
	}
	blocks := map[Count][32]byte{}
	parents := map[string][32]byte{}
	logs := map[string]bool{}
	var lastBlock Count
	var lastLog uint32
	hasLast := false
	for _, event := range f.Events {
		t := event.Transaction
		if pending && (TransactionPosition{t.BlockNumber, t.TransactionIndex, t.Hash}) != after.Events.Parent {
			return ErrUnavailable
		}
		if !c.transaction(t) || t.Status != 1 || t.Hash == ([32]byte{}) || t.BlockHash == ([32]byte{}) || countValue(t.BlockNumber) > 9223372036854775807 || event.LogIndex > 2147483647 {
			return ErrUnavailable
		}
		if old, ok := blocks[t.BlockNumber]; ok && old != t.BlockHash {
			return ErrUnavailable
		}
		blocks[t.BlockNumber] = t.BlockHash
		key := string(t.BlockNumber) + "/" + strconv.FormatUint(uint64(t.TransactionIndex), 10)
		if old, ok := parents[key]; ok && old != t.Hash {
			return ErrUnavailable
		}
		parents[key] = t.Hash
		logKey := string(t.BlockNumber) + "/" + strconv.FormatUint(uint64(event.LogIndex), 10)
		if logs[logKey] {
			return ErrUnavailable
		}
		if hasLast && lastBlock == t.BlockNumber && event.LogIndex <= lastLog {
			return ErrUnavailable
		}
		hasLast, lastBlock, lastLog = true, t.BlockNumber, event.LogIndex
		logs[logKey] = true
		if c.scope.Query.scope.Level == p.Full {
			if event.Payload == nil || event.Payload.Topics == nil || event.Payload.Data == nil || len(event.Payload.Topics) > 4 || len(event.Payload.Data) > MaxResponseBytes {
				return ErrUnavailable
			}
		} else if event.Payload != nil {
			return ErrUnavailable
		}
		index := event.LogIndex
		pos := EventsPosition{Parent: TransactionPosition{t.BlockNumber, t.TransactionIndex, t.Hash}, Mode: "pending", NextLogIndex: &index}
		if !validEventsPosition(pos) || previous != nil && compareEventsPositions(pos, *previous) <= 0 {
			return ErrUnavailable
		}
		if checkInitial && after != nil && compareEventsPositions(pos, *after.Events) < 0 {
			return ErrUnavailable
		}
		previous = &pos
	}
	if f.End {
		if f.Next != nil {
			return ErrUnavailable
		}
		return nil
	}
	if f.Next == nil || f.Next.Events == nil || !validPosition(*f.Next) {
		return ErrUnavailable
	}
	if previous != nil && compareEventsPositions(*f.Next.Events, *previous) <= 0 {
		return ErrUnavailable
	}
	if checkInitial && after != nil && compareEventsPositions(*f.Next.Events, *after.Events) <= 0 {
		return ErrUnavailable
	}
	return nil
}

func eventID(c RenderContext, event EventFact, network Digest) string {
	mac := hmac.New(sha256.New, c.Keys.Active.Bytes)
	generation, _ := RenderGeneration(c.Keys)
	mac.Write(framed([]byte("ops.disclosure.event-id/v1"), []byte(network), []byte(generation), []byte(c.Keys.Active.ID), []byte(c.Namespace), []byte(c.CaseID), []byte(c.DataOrganizationID), []byte(c.RecipientActorID), event.Transaction.BlockHash[:], event.Transaction.Hash[:], []byte(strconv.FormatUint(uint64(event.LogIndex), 10))))
	return "de1." + c.Keys.Active.ID + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

func eventDTO(c RenderContext, event EventFact, network Digest) EventDTO {
	t := event.Transaction
	out := EventDTO{EventID: eventID(c, event, network), BlockNumber: t.BlockNumber, TransactionIndex: t.TransactionIndex, LogIndex: event.LogIndex, BlockTime: t.BlockTime, Emitter: display(c, event.Emitter, true), Payload: "withheld"}
	if c.Query.scope.Level == p.Full {
		out.Payload = "disclosed"
		out.TransactionHash = ptr(hashString(t.Hash))
		out.BlockHash = ptr(hashString(t.BlockHash))
		topics := make([]string, len(event.Payload.Topics))
		for i, topic := range event.Payload.Topics {
			topics[i] = hashString(topic)
		}
		out.Topics = &topics
		out.Data = ptr("0x" + hex.EncodeToString(event.Payload.Data))
	}
	return out
}
