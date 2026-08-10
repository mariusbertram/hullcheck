package jobs

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func waitForTerminalStatus(t *testing.T, mgr *Manager, id string, timeout time.Duration) *Job {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if job := mgr.GetJob(id); job != nil && (job.Status == jobStatusCompleted || job.Status == jobStatusFailed) {
			return job
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s did not reach a terminal status within %s", id, timeout)
	return nil
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
	final := waitForTerminalStatus(t, podB, job.ID, 5*time.Second)
	if final.Status != jobStatusCompleted {
		t.Fatalf("expected job to complete, got status=%s error=%s", final.Status, final.Error)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(ranOn) != 1 {
		t.Fatalf("expected exactly one pod to run the job, ran on %v", ranOn)
	}
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

	regAuth := map[string]string{"authority": "registry.example.com", "username": "u", "password": "hunter2"}
	job := podA.CreateJob("example.com/some/image:latest", regAuth, false, false)

	final := waitForTerminalStatus(t, podA, job.ID, 5*time.Second)
	if final.Status != jobStatusCompleted {
		t.Fatalf("expected job to complete, got status=%s error=%s", final.Status, final.Error)
	}

	// Give a wrongly-claimed cross-pod run a moment to show up before
	// asserting it never happened.
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(ranOn) != 1 || ranOn[0] != "A" {
		t.Fatalf("expected the job to run only on the creating pod, ran on %v", ranOn)
	}
	if gotAuth["password"] != "hunter2" {
		t.Fatalf("expected the ad-hoc credentials to reach the runner, got %v", gotAuth)
	}

	assertNoCredentialsOnDisk(t, dataDir, "hunter2")
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
