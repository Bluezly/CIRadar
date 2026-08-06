package db

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPostgresPoolCloseWakesBlockedAcquire(t *testing.T) {
	pool := newPostgresPool("unused", 1)
	pool.slots <- struct{}{}
	result := make(chan error, 1)
	go func() {
		_, err := pool.acquire(context.Background())
		result <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := pool.close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, errPostgresPoolClosed) {
			t.Fatalf("acquire error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked acquire was not released by close")
	}
}

func TestPostgresPoolAcquireAfterCloseFails(t *testing.T) {
	pool := newPostgresPool("unused", 1)
	if err := pool.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.acquire(context.Background()); !errors.Is(err, errPostgresPoolClosed) {
		t.Fatalf("acquire error=%v", err)
	}
}
