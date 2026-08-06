package db

import (
	"context"
	"errors"
	"sync"
	"time"

	"ciradar/internal/pgwire"
)

const defaultPostgresPoolSize = 10

type postgresPool struct {
	dsn    string
	idle   chan *pgwire.Client
	slots  chan struct{}
	mu     sync.RWMutex
	closed bool
}

func newPostgresPool(dsn string, size int) *postgresPool {
	if size <= 0 {
		size = defaultPostgresPoolSize
	}
	return &postgresPool{
		dsn:   dsn,
		idle:  make(chan *pgwire.Client, size),
		slots: make(chan struct{}, size),
	}
}

func (p *postgresPool) acquire(ctx context.Context) (*pgwire.Client, error) {
	p.mu.RLock()
	closed := p.closed
	p.mu.RUnlock()
	if closed {
		return nil, errors.New("postgres connection pool is closed")
	}

	select {
	case c := <-p.idle:
		return c, nil
	default:
	}

	select {
	case c := <-p.idle:
		return c, nil
	case p.slots <- struct{}{}:
		c, err := pgwire.Connect(ctx, p.dsn)
		if err != nil {
			<-p.slots
			return nil, err
		}
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *postgresPool) release(c *pgwire.Client) {
	if c == nil {
		return
	}
	p.mu.RLock()
	closed := p.closed
	p.mu.RUnlock()
	if closed || !postgresConnectionHealthy(c) {
		_ = c.Close()
		<-p.slots
		return
	}
	select {
	case p.idle <- c:
	default:
		_ = c.Close()
		<-p.slots
	}
}

func postgresConnectionHealthy(c *pgwire.Client) bool {
	if c == nil || c.Broken() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// ROLLBACK is harmless outside a transaction and guarantees that a caller
	// cannot return an aborted/open transaction to the shared pool.
	if err := c.Exec(ctx, "ROLLBACK"); err != nil {
		return false
	}
	return c.Exec(ctx, "SELECT 1") == nil
}

func (p *postgresPool) close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()

	for {
		select {
		case c := <-p.idle:
			_ = c.Close()
			<-p.slots
		default:
			return nil
		}
	}
}
