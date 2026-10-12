package events

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHubBroadcast(t *testing.T) {
	hub := NewHub[string]()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	events := hub.Subscribe(ctx)

	require.NoError(t, hub.Broadcast(t.Context(), "hello"))
	assert.Equal(t, "hello", <-events)
}

func TestReplayHubDeliversLastEventToLateSubscriber(t *testing.T) {
	hub := NewReplayHub[string]()

	// No event yet - new subscribers have nothing to replay
	idleCtx, cancelIdle := context.WithCancel(t.Context())
	idle := hub.Subscribe(idleCtx)
	select {
	case <-idle:
		t.Fatal("unexpected event before first broadcast")
	case <-time.After(20 * time.Millisecond):
	}

	require.NoError(t, hub.Broadcast(t.Context(), "generation-1"))

	// Drain and then stop the idle subscriber. Its unregistration happens
	// asynchronously, so keep its buffer empty for broadcasts in the meantime.
	assert.Equal(t, "generation-1", <-idle)
	cancelIdle()

	// A subscriber that connects later replays the current generation without
	// another event being produced
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	late := hub.Subscribe(ctx)
	select {
	case event := <-late:
		assert.Equal(t, "generation-1", event)
	case <-time.After(time.Second):
		t.Fatal("late subscriber did not receive the replayed event")
	}

	// Live events continue to be delivered after the replay
	require.NoError(t, hub.Broadcast(t.Context(), "generation-2"))
	assert.Equal(t, "generation-2", <-late)
}

func TestReplayHubDoesNotAdvanceOnFailedBroadcast(t *testing.T) {
	hub := NewReplayHub[string]()

	// A subscriber whose buffer fills up and which never drains it blocks later
	// broadcasts
	blockingCtx, cancelBlocking := context.WithCancel(t.Context())
	hub.Subscribe(blockingCtx)

	// Fills the subscriber's buffer and becomes the last confirmed event
	require.NoError(t, hub.Broadcast(t.Context(), "generation-1"))

	// The second broadcast cannot be delivered and fails with the context
	// expiring. It must not replace the replayed generation.
	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()
	err := hub.Broadcast(canceledCtx, "undelivered")
	require.ErrorIs(t, err, context.Canceled)

	cancelBlocking()

	ctx, cancel2 := context.WithCancel(t.Context())
	defer cancel2()
	events := hub.Subscribe(ctx)
	select {
	case event := <-events:
		assert.Equal(t, "generation-1", event)
	case <-time.After(time.Second):
		t.Fatal("failed broadcast must not replace the replayed generation")
	}

	// Seeding primes replay for a generation confirmed before startup
	hub.Seed("generation-0")
	seeded := hub.Subscribe(ctx)
	select {
	case event := <-seeded:
		assert.Equal(t, "generation-0", event)
	case <-time.After(time.Second):
		t.Fatal("seeded subscriber did not receive the replayed event")
	}
}
