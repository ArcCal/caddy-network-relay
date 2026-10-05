package networkrelay

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Includes the load generator and server in one process. This checks resource
// bounds and recovery, not a production throughput or device certification.
func TestDeploymentCapacity(t *testing.T) {
	n := 128
	if raw := os.Getenv("RELAY_CAPACITY_CLIENTS"); raw != "" {
		var err error
		n, err = strconv.Atoi(raw)
		if err != nil || n < 1 || n > 1000 {
			t.Fatal("RELAY_CAPACITY_CLIENTS must be 1..1000")
		}
	}
	users := make([]map[string]string, n)
	for i := range users {
		users[i] = map[string]string{"name": fmt.Sprintf("device-%04d", i), "password_hash": testHash}
	}
	cfg := map[string]any{"users": users, "max_tunnels": n, "max_tunnels_per_user": 2}
	// Every device here dials from 127.0.0.1; on a network each has its own address.
	h3ClientLimit(t, n)
	port, reload := startRelay(t, cfg, nil)
	target := echoTCP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	beforeFD, _ := os.ReadDir("/proc/self/fd")
	conns := make([]*h3Conn, n)
	streams := make([]stream, n)
	latency := make([]time.Duration, n)
	defer func() {
		for i := range streams {
			if streams[i] != nil {
				streams[i].Close()
			}
			if conns[i] != nil {
				conns[i].Close()
			}
		}
	}()
	work := make(chan int)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				start := time.Now()
				c := client(port)
				c.Authorization = BasicAuthorization(users[i]["name"], testPassword)
				h, err := c.dialH3(ctx)
				if err != nil {
					errs <- err
					continue
				}
				conns[i] = h
				s, err := c.openTCPH3(ctx, h, target)
				if err != nil {
					errs <- err
					continue
				}
				streams[i] = s
				payload := bytes.Repeat([]byte{byte(i)}, 1024)
				if _, err = s.Write(payload); err != nil {
					errs <- err
					continue
				}
				got := make([]byte, len(payload))
				if _, err = io.ReadFull(s, got); err != nil {
					errs <- err
					continue
				}
				if !bytes.Equal(got, payload) {
					errs <- fmt.Errorf("device %d data corrupted", i)
					continue
				}
				latency[i] = time.Since(start)
			}
		}()
	}
	for i := range users {
		work <- i
	}
	close(work)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	if got := openTunnels.Load(); got != int64(n) {
		t.Fatalf("%d open tunnels, want %d", got, n)
	}
	runtime.GC()
	var peak runtime.MemStats
	runtime.ReadMemStats(&peak)
	if growth := int64(peak.HeapInuse) - int64(before.HeapInuse); growth > int64(n)*(1<<20)+(64<<20) {
		t.Fatalf("unbounded heap growth: %d bytes for %d devices", growth, n)
	}
	fd, _ := os.ReadDir("/proc/self/fd")
	sort.Slice(latency, func(i, j int) bool { return latency[i] < latency[j] })
	t.Logf("%d separate H3 connections and accounts: heap growth %.1f MiB, FD growth %d, admission p50=%v p99=%v", n, float64(int64(peak.HeapInuse)-int64(before.HeapInuse))/(1<<20), len(fd)-len(beforeFD), latency[n/2], latency[(n-1)*99/100])
	// Existing tunnels survive a same-domain reload. No new tunnel may
	// bypass the process ceiling while all old tunnels remain active.
	reload(cfg)
	c := client(port)
	c.Authorization = BasicAuthorization(users[0]["name"], testPassword)
	extra, err := c.openTCPH3(ctx, conns[0], target)
	if err == nil {
		extra.Close()
		t.Fatal("process tunnel ceiling bypassed")
	}
	for i, s := range streams {
		payload := []byte("after reload")
		if _, err := s.Write(payload); err != nil {
			t.Fatalf("device %d reload write: %v", i, err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(s, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("device %d reload response: %v", i, err)
		}
		s.Close()
		conns[i].Close()
	}
	deadline := time.Now().Add(10 * time.Second)
	for openTunnels.Load() != 0 || h3Connections.open() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("resources leaked: tunnels=%d H3=%d", openTunnels.Load(), h3Connections.open())
		}
		time.Sleep(10 * time.Millisecond)
	}
	userTunnels.Lock()
	left := len(userTunnels.counts)
	userTunnels.Unlock()
	if left != 0 {
		t.Fatalf("%d user quota entries leaked", left)
	}
}
