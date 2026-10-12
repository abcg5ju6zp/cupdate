package events

import (
	"context"
	"sync"
)

// Hub is an event hub allowing broadcasting of events to subscribers.
type Hub[T any] struct {
	mutex    sync.Mutex
	channels map[chan T]struct{}
	// replay, when true, makes the hub remember the last confirmed event and
	// deliver it first to new subscribers, allowing subscribers that were
	// temporarily disconnected to catch up on the current generation without
	// anyone producing another event.
	replay bool
	last   *T
}

func NewHub[T any]() *Hub[T] {
	return &Hub[T]{
		channels: make(map[chan T]struct{}),
	}
}

// NewReplayHub returns a [Hub] that remembers the last confirmed event and
// replays it to subscribers when they subscribe. This lets temporarily
// disconnected subscribers catch up on the current generation without a new
// event being produced.
func NewReplayHub[T any]() *Hub[T] {
	return &Hub[T]{
		channels: make(map[chan T]struct{}),
		replay:   true,
	}
}

// Subscribe to events.
// Returns a channel which will receives all broadcast events.
// The channel is closed whenever the context expires.
// Subscribers should receive events from the channel in a timely manner.
//
// On replay hubs, the channel first delivers the last confirmed event, if any,
// before any live event.
func (h *Hub[T]) Subscribe(ctx context.Context) <-chan T {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	// Use a buffered channel so a replayed event (if any) can be seeded while
	// the hub mutex is held without blocking or racing with channel closure.
	ch := make(chan T, 1)

	if h.replay && h.last != nil {
		ch <- *h.last
	}

	go func() {
		<-ctx.Done()
		h.mutex.Lock()
		defer h.mutex.Unlock()

		delete(h.channels, ch)

		close(ch)
	}()

	h.channels[ch] = struct{}{}

	return ch
}

// Broadcast an event to all subscribers synchronously.
// Returns an error if the context expires before all subscribers were invoked.
//
// On replay hubs, the event is remembered for late subscribers only once it was
// delivered to all current subscribers, so a blocked or failed broadcast does
// not advance the replayed generation.
func (h *Hub[T]) Broadcast(ctx context.Context, event T) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	for ch := range h.channels {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ch <- event:
		}
	}

	if h.replay {
		last := event
		h.last = &last
	}

	return nil
}

// Seed provides the event that replay hubs hand to new subscribers before any
// live event is broadcast. It is used to prime the hub with the generation that
// was confirmed before the process started, e.g. when recovering after a
// restart. It has no effect on non-replay hubs.
func (h *Hub[T]) Seed(event T) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if !h.replay {
		return
	}

	last := event
	h.last = &last
}
