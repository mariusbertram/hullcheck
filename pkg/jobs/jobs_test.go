package jobs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// terminalStatusTimeout bounds waitForTerminalStatus - every test scan here
// runs a nil/no-op runner, so this only needs to cover scheduling/dispatch
// latency, not real scanning work.
const terminalStatusTimeout = 5 * time.Second

// testAdHocPassword is a stand-in ad-hoc registry credential shared by the
// tests that need one, guarding that it reaches the runner and never
// touches disk.
const testAdHocPassword = "hunter2"

func waitForTerminalStatus(t *testing.T, mgr *Manager, id string) *Job {
	t.Helper()
	deadline := time.Now().Add(terminalStatusTimeout)
	for time.Now().Before(deadline) {
		if job := mgr.GetJob(id); job != nil && (job.Status == jobStatusCompleted || job.Status == jobStatusFailed) {
			return job
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s did not reach a terminal status within %s", id, terminalStatusTimeout)
	return nil
}

// waitIdle blocks until mgr has no scans running and every disk write it
// queued (see enqueuePersist/persistWorker) has actually landed. Tests call
// this before returning - a background write still in flight when
// t.TempDir() cleans up races "directory not empty", since Manager's
// worker goroutines don't stop just because a test function returns.
func waitIdle(t *testing.T, mgr *Manager) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mgr.WaitIdle(ctx)
	if ctx.Err() != nil {
		t.Fatal("manager did not go idle in time")
	}
}

func newTestManager(t *testing.T, dataDir, name string, ranOn *[]string, mu *sync.Mutex, onRun func(job *Job, regAuth map[string]string)) *Manager {
	t.Helper()
	mgr, err := NewManager(dataDir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	mgr.SetRunner(func(job *Job, regAuth map[string]string) {
		mu.Lock()
		*ranOn = append(*ranOn, name)
		mu.Unlock()
		if onRun != nil {
			onRun(job, regAuth)
		}
	})
	return mgr
}

// TestCreateJob_SharedQueue_ClaimedByExactlyOnePod simulates two pods
// sharing the same PVC (dataDir): a job created with no ad-hoc registry
// credentials must go through the shared queue and be picked up by exactly
// one of them, never both (see claimNext's rename-based atomic claim) and
// never neither (it must still complete somewhere).
func TestCreateJob_SharedQueue_ClaimedByExactlyOnePod(t *testing.T) {
	t.Setenv("QUEUE_POLL_INTERVAL_MS", "20")
	dataDir := t.TempDir()

	var mu sync.Mutex
	var ranOn []string
	podA := newTestManager(t, dataDir, "A", &ranOn, &mu, nil)
	podB := newTestManager(t, dataDir, "B", &ranOn, &mu, nil)

	job := podA.CreateJob("example.com/some/image:latest", nil, false, false)

	// Regardless of which pod actually ran it, the shared job.json on disk
	// must reflect that - GetJob falls back to disk for a job this pod
	// didn't claim itself.
	final := waitForTerminalStatus(t, podB, job.ID)
	if final.Status != jobStatusCompleted {
		t.Fatalf("expected job to complete, got status=%s error=%s", final.Status, final.Error)
	}

	mu.Lock()
	ok := len(ranOn) == 1
	mu.Unlock()
	if !ok {
		t.Fatalf("expected exactly one pod to run the job, ran on %v", ranOn)
	}

	// Whichever pod actually ran it did so on a background goroutine that
	// keeps running (and writing under dataDir) after this test function
	// returns unless drained first - t.TempDir()'s cleanup would otherwise
	// race it.
	waitIdle(t, podA)
	waitIdle(t, podB)
}

// TestCreateJob_AdHocCredentials_StayLocal verifies a job created with
// per-scan registry credentials (the UI's "Advanced" section, or Harbor's
// per-scan robot-account token) is pinned to the pod that created it and
// never written to the shared PVC queue in any form - other pods sharing
// the same dataDir must never see it, and the raw credential must never
// touch disk.
func TestCreateJob_AdHocCredentials_StayLocal(t *testing.T) {
	t.Setenv("QUEUE_POLL_INTERVAL_MS", "20")
	dataDir := t.TempDir()

	var mu sync.Mutex
	var ranOn []string
	var gotAuth map[string]string
	podA := newTestManager(t, dataDir, "A", &ranOn, &mu, func(job *Job, regAuth map[string]string) {
		mu.Lock()
		gotAuth = regAuth
		mu.Unlock()
	})
	_ = newTestManager(t, dataDir, "B", &ranOn, &mu, nil)

	regAuth := map[string]string{"authority": "registry.example.com", "username": "u", "password": testAdHocPassword}
	job := podA.CreateJob("example.com/some/image:latest", regAuth, false, false)

	final := waitForTerminalStatus(t, podA, job.ID)
	if final.Status != jobStatusCompleted {
		t.Fatalf("expected job to complete, got status=%s error=%s", final.Status, final.Error)
	}
	waitIdle(t, podA)

	// Give a wrongly-claimed cross-pod run a moment to show up before
	// asserting it never happened.
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	ranOnCopy := append([]string(nil), ranOn...)
	mu.Unlock()
	if len(ranOnCopy) != 1 || ranOnCopy[0] != "A" {
		t.Fatalf("expected the job to run only on the creating pod, ran on %v", ranOnCopy)
	}
	if gotAuth["password"] != testAdHocPassword {
		t.Fatalf("expected the ad-hoc credentials to reach the runner, got %v", gotAuth)
	}

	assertNoCredentialsOnDisk(t, dataDir, testAdHocPassword)
}

// TestCreateJobPersistsSynchronouslyBeforeDispatch guards a regression hit
// while decoupling disk I/O from m.mu (see persistJob/persistJobSync):
// making persistJob asynchronous meant a worker could claim a freshly
// enqueued job and try to adopt it (readFullJob) before job.json actually
// existed on disk yet, since enqueueShared/localQueue fired before the
// async write had run. CreateJob's very first write must stay synchronous
// so job.json is guaranteed to exist the moment CreateJob returns, for both
// dispatch paths.
func TestCreateJobPersistsSynchronouslyBeforeDispatch(t *testing.T) {
	dataDir := t.TempDir()

	t.Run("shared queue path", func(t *testing.T) {
		mgr, err := NewManager(dataDir)
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		job := mgr.CreateJob("example.com/some/image:latest", nil, false, false)
		path := filepath.Join(dataDir, "scans", job.ID, "job.json")
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist immediately after CreateJob returns, got: %v", path, err)
		}
		// Let the job finish before this subtest returns - t.TempDir()'s
		// cleanup runs once the parent test returns, and a still-running
		// worker would otherwise still be writing under dataDir at that point.
		waitForTerminalStatus(t, mgr, job.ID)
		waitIdle(t, mgr)
	})

	t.Run("ad-hoc credentials path", func(t *testing.T) {
		mgr, err := NewManager(dataDir)
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		regAuth := map[string]string{"authority": "registry.example.com", "password": testAdHocPassword}
		job := mgr.CreateJob("example.com/some/image:latest", regAuth, false, false)
		path := filepath.Join(dataDir, "scans", job.ID, "job.json")
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist immediately after CreateJob returns, got: %v", path, err)
		}
		waitForTerminalStatus(t, mgr, job.ID)
		waitIdle(t, mgr)
	})
}

// TestAppendLogDoesNotBlockOnSlowDiskWrite guards the actual bug behind
// Harbor's report-polling timeouts: AppendLog (and persistJob) must never
// hold m.mu - the same lock GetJob/IsLocal need, which every GetReport call
// depends on - across a disk write. Simulates a stalled PVC write by
// wedging the persist worker on a task that blocks until released, then
// asserts AppendLog and GetJob both keep returning promptly regardless.
func TestAppendLogDoesNotBlockOnSlowDiskWrite(t *testing.T) {
	dataDir := t.TempDir()
	mgr, err := NewManager(dataDir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	job := mgr.CreateJob("example.com/some/image:latest", nil, false, false)

	release := make(chan struct{})
	started := make(chan struct{})
	mgr.enqueuePersist(func() {
		close(started)
		<-release
	})
	<-started // the single persist worker is now stuck until we release it

	const bound = 2 * time.Second // generous - well under Harbor's real 5s per-call client timeout

	appendDone := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			mgr.AppendLog(job.ID, "syft", "info", "line")
		}
		close(appendDone)
	}()
	select {
	case <-appendDone:
	case <-time.After(bound):
		close(release)
		t.Fatal("AppendLog blocked while the persist worker was stalled - m.mu is being held across disk I/O again")
	}

	getDone := make(chan struct{})
	go func() {
		mgr.GetJob(job.ID)
		close(getDone)
	}()
	select {
	case <-getDone:
	case <-time.After(bound):
		close(release)
		t.Fatal("GetJob blocked while the persist worker was stalled")
	}

	// Unstick the worker and let it fully drain the backlog (the ~50
	// AppendLog writes plus executeJob's own status writes) before this
	// test returns - otherwise those writes can still be landing under
	// dataDir when t.TempDir()'s cleanup runs, racing "directory not empty".
	close(release)
	waitIdle(t, mgr)
}

// assertNoCredentialsOnDisk fails the test if secret appears anywhere under
// dataDir/queue - CreateJob must never write ad-hoc registry credentials to
// the shared PVC queue (see QueueItem's doc comment).
func assertNoCredentialsOnDisk(t *testing.T, dataDir, secret string) {
	t.Helper()
	queueDir := filepath.Join(dataDir, "queue")
	_ = filepath.Walk(queueDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr == nil && bytes.Contains(data, []byte(secret)) {
			t.Fatalf("queue entry %s contains credential material", path)
		}
		return nil
	})
}
