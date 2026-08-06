package db

import (
	"context"
	"errors"
	"sync"
	"time"

	"ciradar/internal/pgwire"
)

const defaultPostgresPoolSize = 10

var errPostgresPoolClosed = errors.New("postgres connection pool is closed")

type postgresPool struct {
	dsn     string
	idle    chan *pgwire.Client
	slots   chan struct{}
	closeCh chan struct{}
	mu      sync.RWMutex
	closed  bool
}

func newPostgresPool(dsn string, size int) *postgresPool {
	if size <= 0 {
		size = defaultPostgresPoolSize
	}
	return &postgresPool{
		dsn:     dsn,
		idle:    make(chan *pgwire.Client, size),
		slots:   make(chan struct{}, size),
		closeCh: make(chan struct{}),
	}
}

func (p *postgresPool) isClosed() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.closed
}

func (p *postgresPool) acquire(ctx context.Context) (*pgwire.Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.isClosed() {
		return nil, errPostgresPoolClosed
	}

	select {
	case <-p.closeCh:
		return nil, errPostgresPoolClosed
	case c := <-p.idle:
		if p.isClosed() {
			_ = c.Close()
			<-p.slots
			return nil, errPostgresPoolClosed
		}
		return c, nil
	default:
	}

	select {
	case <-p.closeCh:
		return nil, errPostgresPoolClosed
	case c := <-p.idle:
		if p.isClosed() {
			_ = c.Close()
			<-p.slots
			return nil, errPostgresPoolClosed
		}
		return c, nil
	case p.slots <- struct{}{}:
		if p.isClosed() {
			<-p.slots
			return nil, errPostgresPoolClosed
		}
		c, err := pgwire.Connect(ctx, p.dsn)
		if err != nil {
			<-p.slots
			return nil, err
		}
		if p.isClosed() {
			_ = c.Close()
			<-p.slots
			return nil, errPostgresPoolClosed
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
	if p.isClosed() || !postgresConnectionHealthy(c) {
		_ = c.Close()
		<-p.slots
		return
	}
	select {
	case <-p.closeCh:
		_ = c.Close()
		<-p.slots
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
	close(p.closeCh)
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
