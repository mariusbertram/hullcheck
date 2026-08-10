package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const maxLogLines = 4000

// jobStatusFailed is the terminal Job.Status value for a scan that errored
// out (as opposed to a ToolStatus's own "failed" value, which reads the
// same but is set independently per tool).
const jobStatusFailed = "failed"

// jobStatusCompleted is the terminal Job.Status value for a scan that
// finished without error.
const jobStatusCompleted = "completed"

// toolStatusPending is a ToolStatus's initial state before a tool starts running.
const toolStatusPending = "pending"

// eventTypeStatus identifies a Broadcast Event carrying a Job status snapshot.
const eventTypeStatus = "status"

// claimedSubdir is where claimNext atomically moves a shared queue entry
// (queueDir/<name>) before reading it, so a losing rename (ENOENT - another
// pod's worker already claimed it) is indistinguishable from a name that
// was never there. It's a subdirectory of queueDir rather than a sibling so
// both live on the same filesystem/PVC - os.Rename across filesystems isn't
// atomic (and often isn't even supported).
const claimedSubdir = "claimed"

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

type ToolStatus struct {
	Status     string `json:"status"` // "pending", "running", "success", "failed", "error", "timeout"
	ExitCode   *int   `json:"exitCode"`
	StartedAt  *int64 `json:"startedAt,omitempty"`
	FinishedAt *int64 `json:"finishedAt,omitempty"`
}

type LogEntry struct {
	TS     int64  `json:"ts"`
	Tool   string `json:"tool"`
	Stream string `json:"stream"` // "info", "stderr", "stdout"
	Text   string `json:"text"`
}

type JobOptions struct {
	RegistryAuthAuthority string `json:"registryAuthAuthority,omitempty"`
	InsecureSkipTLSVerify bool   `json:"insecureSkipTlsVerify"`
	InsecureUseHTTP       bool   `json:"insecureUseHttp"`
}

type GrypeSummary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"bySeverity"`
}

type SyftSummary struct {
	PackageCount int            `json:"packageCount"`
	ByType       map[string]int `json:"byType"`
	Distro       string         `json:"distro,omitempty"`
}

type GrantSummary struct {
	PackageCount   int            `json:"packageCount"`
	LicenseCounts  map[string]int `json:"licenseCounts"`
	WithoutLicense int            `json:"withoutLicense"`
	Raw            bool           `json:"raw,omitempty"`
}

type Summary struct {
	Syft  *SyftSummary  `json:"syft,omitempty"`
	Grype *GrypeSummary `json:"grype,omitempty"`
	Grant *GrantSummary `json:"grant,omitempty"`
}

type Job struct {
	ID         string                 `json:"id"`
	Image      string                 `json:"image"`
	Status     string                 `json:"status"` // "queued", "running", "completed", "failed"
	CreatedAt  int64                  `json:"createdAt"`
	StartedAt  *int64                 `json:"startedAt"`
	FinishedAt *int64                 `json:"finishedAt"`
	Options    JobOptions             `json:"options"`
	Tools      map[string]*ToolStatus `json:"tools"`
	Summary    *Summary               `json:"summary"`
	Error      string                 `json:"error,omitempty"`
	Logs       []LogEntry             `json:"logs,omitempty"`
}

type JobSummary struct {
	ID         string                 `json:"id"`
	Image      string                 `json:"image"`
	Status     string                 `json:"status"`
	CreatedAt  int64                  `json:"createdAt"`
	StartedAt  *int64                 `json:"startedAt"`
	FinishedAt *int64                 `json:"finishedAt"`
	Tools      map[string]*ToolStatus `json:"tools"`
	Summary    *Summary               `json:"summary"`
	Error      string                 `json:"error,omitempty"`
}

// cloneToolsMap and cloneSummary make independent copies of the mutable
// parts of a Job so a *Job handed outside m.mu (for JSON encoding or SSE
// broadcast) can't data-race with a worker goroutine still mutating the
// live job in place (SetToolStatus/SetSummary mutate existing *ToolStatus
// and *Summary values, they don't just swap pointers).
func cloneToolsMap(src map[string]*ToolStatus) map[string]*ToolStatus {
	out := make(map[string]*ToolStatus, len(src))
	for k, v := range src {
		vv := *v
		out[k] = &vv
	}
	return out
}

func cloneSummary(src *Summary) *Summary {
	if src == nil {
		return nil
	}
	s := *src
	return &s
}

// cloneJob assumes the caller holds m.mu (read or write).
func cloneJob(j *Job) *Job {
	c := *j
	c.Tools = cloneToolsMap(j.Tools)
	c.Summary = cloneSummary(j.Summary)
	c.Logs = append([]LogEntry(nil), j.Logs...)
	return &c
}

// QueueItem is a unit of dispatch: either handed straight to this pod's
// worker pool in memory (localQueue) or, once marshaled to JSON, written to
// queueDir on the shared PVC for any pod's worker pool to claim.
//
// RegistryAuth only ever travels the in-memory path. A CreateJob call whose
// regAuth carries actual credentials (username/password/token - typed
// one-off into the UI's "Advanced" section, or Harbor's per-scan
// robot-account token/basic-auth header) never reaches the shared queue at
// all and is pushed to localQueue instead, so those credentials are never
// written to disk (see README's Security notes) - which also means such a
// job can only ever run on the pod that created it. Everything else (no
// per-scan credentials, or a bare authority already configured globally via
// the mounted pull secret / UI config - see config.Manager.BuildRegistryOptions)
// goes through the shared queue with RegistryAuth left nil/empty, so any
// pod can claim and run it.
type QueueItem struct {
	JobID        string            `json:"jobId"`
	RegistryAuth map[string]string `json:"-"`
}

type Event struct {
	Type string      `json:"type"` // "status", "log", "done"
	Data interface{} `json:"data"`
}

type Manager struct {
	mu       sync.RWMutex
	scansDir string
	queueDir string
	// jobs holds only jobs this process is actively running or has run -
	// either created here with ad-hoc registry credentials (pinned to this
	// pod, see CreateJob) or claimed off the shared queue (queueDir) by one
	// of this pod's own workers. A multi-pod deployment shares scansDir and
	// queueDir but not memory: every other pod's jobs live only on disk as
	// far as this process is concerned, so GetJob/IsLocal treat presence
	// here as "this pod owns it" and fall back to disk for everything else
	// (see GetJob).
	jobs        map[string]*Job
	subscribers map[string][]chan Event
	subMu       sync.RWMutex
	runner      func(job *Job, regAuth map[string]string)
	// localQueue carries jobs pinned to this pod (ad-hoc registry
	// credentials - see CreateJob/QueueItem) straight to its own worker
	// pool, bypassing the shared queue entirely.
	localQueue chan QueueItem
	// wake nudges an idle local worker to recheck queueDir immediately
	// after this pod enqueues a shared job, instead of waiting for the next
	// poll tick - the common case (this pod has a free worker) then starts
	// with no perceptible delay, while other pods still pick the job up via
	// polling if this one doesn't get to it first.
	wake       chan struct{}
	maxHistory int
	activeWG   sync.WaitGroup
}

func NewManager(dataDir string) (*Manager, error) {
	scansDir := filepath.Join(dataDir, "scans")
	if err := os.MkdirAll(scansDir, 0755); err != nil {
		return nil, err
	}
	queueDir := filepath.Join(dataDir, "queue")
	if err := os.MkdirAll(filepath.Join(queueDir, claimedSubdir), 0700); err != nil {
		return nil, err
	}

	concurrency := envInt("MAX_CONCURRENCY", 2)
	maxHistory := envInt("MAX_HISTORY", 200)
	pollInterval := time.Duration(envInt("QUEUE_POLL_INTERVAL_MS", 2000)) * time.Millisecond

	m := &Manager{
		scansDir:    scansDir,
		queueDir:    queueDir,
		jobs:        make(map[string]*Job),
		subscribers: make(map[string][]chan Event),
		localQueue:  make(chan QueueItem, 500),
		wake:        make(chan struct{}, concurrency),
		maxHistory:  maxHistory,
	}

	go m.workerPool(concurrency, pollInterval)
	log.Printf("jobs: worker pool started (concurrency=%d, maxHistory=%d, queuePollInterval=%s)", concurrency, maxHistory, pollInterval)

	return m, nil
}

func (m *Manager) SetRunner(fn func(job *Job, regAuth map[string]string)) {
	m.runner = fn
}

// workerPool runs concurrency workers, each preferring a job pinned to this
// pod (localQueue) over claiming one from the shared PVC queue (claimNext)
// so a job with ad-hoc credentials never waits behind cross-pod work this
// pod could run immediately; either source feeds the same execution path.
func (m *Manager) workerPool(concurrency int, pollInterval time.Duration) {
	for i := 0; i < concurrency; i++ {
		workerID := i
		go func() {
			ticker := time.NewTicker(pollInterval)
			defer ticker.Stop()
			for {
				select {
				case item := <-m.localQueue:
					m.runQueued(workerID, item)
					continue
				default:
				}
				if item, ok := m.claimNext(); ok {
					m.runQueued(workerID, item)
					continue
				}
				select {
				case item := <-m.localQueue:
					m.runQueued(workerID, item)
				case <-m.wake:
				case <-ticker.C:
				}
			}
		}()
	}
}

func (m *Manager) runQueued(workerID int, item QueueItem) {
	m.activeWG.Add(1)
	m.executeJobSafely(workerID, item)
	m.activeWG.Done()
}

// claimNext atomically claims the oldest unclaimed entry on the shared PVC
// queue (queueDir), if any, so any pod - not just the one that created the
// job - can pick it up and run it. Claiming is a rename into
// queueDir/claimed: POSIX (and NFS, matching the atomicity persistJob
// already relies on for job.json) guarantees at most one renamer wins when
// multiple pods' workers race for the same filename, so two pods can never
// run the same job.
func (m *Manager) claimNext() (QueueItem, bool) {
	entries, err := os.ReadDir(m.queueDir)
	if err != nil {
		return QueueItem{}, false
	}
	claimedDir := filepath.Join(m.queueDir, claimedSubdir)

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	// Filenames are zero-padded-createdAt-prefixed (see enqueueShared), so
	// lexicographic order is chronological order - oldest job first.
	sort.Strings(names)

	for _, name := range names {
		src := filepath.Join(m.queueDir, name)
		dst := filepath.Join(claimedDir, name)
		if err := os.Rename(src, dst); err != nil {
			// Lost the race to another worker (this pod's or another pod's) -
			// or a leftover .tmp from a write still in progress; either way,
			// move on to the next candidate.
			continue
		}
		data, err := os.ReadFile(dst)
		_ = os.Remove(dst) // one-shot handoff; the job's real state lives in job.json
		if err != nil {
			log.Printf("jobs: claimed queue entry %s but failed to read it: %v", name, err)
			continue
		}
		var item QueueItem
		if err := json.Unmarshal(data, &item); err != nil {
			log.Printf("jobs: claimed queue entry %s has invalid JSON: %v", name, err)
			continue
		}
		return item, true
	}
	return QueueItem{}, false
}

// enqueueShared publishes id onto the shared PVC queue so any pod's worker
// pool can claim it via claimNext. Written via temp file + rename (like
// persistJob) so a concurrent ReadDir on another pod never sees a
// partially-written entry.
func (m *Manager) enqueueShared(id string, createdAt int64) {
	data, err := json.Marshal(QueueItem{JobID: id})
	if err != nil {
		log.Printf("jobs: failed to encode queue entry for %s: %v", id, err)
		return
	}

	name := fmt.Sprintf("%020d-%s.json", createdAt, id)
	final := filepath.Join(m.queueDir, name)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		log.Printf("jobs: failed to write queue entry for %s: %v", id, err)
		return
	}
	if err := os.Rename(tmp, final); err != nil {
		log.Printf("jobs: failed to publish queue entry for %s: %v", id, err)
		return
	}

	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// WaitIdle blocks until this process has no scans actively running, or ctx
// is done. Graceful shutdown calls this after closing the HTTP listener so
// a scan already running here (its worker goroutine isn't tied to any HTTP
// handler) gets to finish instead of being abandoned mid-run - which would
// otherwise leave the job stuck "running" forever, and any pod polling it
// via the disk-tail fallback stuck watching a file that will never change
// again.
func (m *Manager) WaitIdle(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		m.activeWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// executeJobSafely recovers from panics in executeJob (e.g. a bug in a
// runner) so one bad job can't permanently kill a worker goroutine and
// silently shrink the pool's concurrency.
func (m *Manager) executeJobSafely(workerID int, item QueueItem) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("jobs: worker %d PANIC while running job %s: %v", workerID, item.JobID, r)
			m.mu.Lock()
			job, exists := m.jobs[item.JobID]
			var clone *Job
			if exists {
				job.Error = "internal error while scanning (see server logs)"
				finishTime := time.Now().UnixMilli()
				job.FinishedAt = &finishTime
				job.Status = jobStatusFailed
				m.persistJob(job)
				clone = cloneJob(job)
			}
			m.mu.Unlock()
			if exists {
				m.Broadcast(item.JobID, Event{Type: eventTypeStatus, Data: clone})
				m.Broadcast(item.JobID, Event{Type: "done", Data: clone})
			}
		}
	}()
	m.executeJob(item)
}

func (m *Manager) executeJob(item QueueItem) {
	m.mu.Lock()
	job, exists := m.jobs[item.JobID]
	if !exists {
		// Claimed off the shared PVC queue rather than pinned to this pod via
		// CreateJob - adopt it from its persisted job.json so the rest of
		// this function, and every SetToolStatus/AppendLog/SetSummary/
		// SetError call the runner makes for it, work exactly as if this pod
		// had created it. From here on IsLocal(item.JobID) is true on this
		// pod: it now owns broadcasting this job's live SSE events.
		job = m.readFullJob(item.JobID)
		if job == nil {
			m.mu.Unlock()
			log.Printf("jobs: claimed queue entry for %s but its job.json is missing, skipping", item.JobID)
			return
		}
		m.jobs[item.JobID] = job
	}
	now := time.Now().UnixMilli()
	job.Status = "running"
	job.StartedAt = &now
	m.persistJob(job)
	startClone := cloneJob(job)
	m.mu.Unlock()

	log.Printf("jobs: scan %s started (image=%s)", job.ID, job.Image)
	m.Broadcast(job.ID, Event{Type: eventTypeStatus, Data: startClone})

	if m.runner != nil {
		m.runner(job, item.RegistryAuth)
	}

	m.mu.Lock()
	finishTime := time.Now().UnixMilli()
	job.FinishedAt = &finishTime
	jobErr := job.Error
	if jobErr != "" {
		job.Status = jobStatusFailed
	} else {
		job.Status = jobStatusCompleted
	}
	m.persistJob(job)
	doneClone := cloneJob(job)
	m.mu.Unlock()

	if jobErr != "" {
		log.Printf("jobs: scan %s failed (image=%s): %s", job.ID, job.Image, jobErr)
	} else {
		log.Printf("jobs: scan %s completed (image=%s)", job.ID, job.Image)
	}

	m.Broadcast(job.ID, Event{Type: eventTypeStatus, Data: doneClone})
	m.Broadcast(job.ID, Event{Type: "done", Data: doneClone})
}

func (m *Manager) CreateJob(image string, regAuth map[string]string, insecureTLS, insecureHTTP bool) *Job {
	id := uuid.New().String()
	now := time.Now().UnixMilli()

	authority := ""
	if regAuth != nil {
		authority = regAuth["authority"]
	}

	job := &Job{
		ID:        id,
		Image:     image,
		Status:    "queued",
		CreatedAt: now,
		Options: JobOptions{
			RegistryAuthAuthority: authority,
			InsecureSkipTLSVerify: insecureTLS,
			InsecureUseHTTP:       insecureHTTP,
		},
		Tools: map[string]*ToolStatus{
			"syft":  {Status: toolStatusPending},
			"grype": {Status: toolStatusPending},
			"grant": {Status: toolStatusPending},
		},
		Summary: &Summary{},
		Logs:    []LogEntry{},
	}

	_ = os.MkdirAll(filepath.Join(m.scansDir, id), 0755)

	// Ad-hoc per-scan registry credentials (typed into the UI's "Advanced"
	// section, or Harbor's per-scan robot-account token/basic-auth header)
	// live only in this process's memory and are never written to disk (see
	// README's Security notes) - such a job is pinned to this pod via
	// localQueue and can only ever run here, exactly as before. Everything
	// else (no per-scan credentials, or a bare authority reference already
	// configured globally via the mounted pull secret / UI config) is safe
	// to hand off to any pod, so it goes on the shared PVC queue instead -
	// see QueueItem and enqueueShared.
	hasAdHocCredentials := regAuth != nil && (regAuth["username"] != "" || regAuth["password"] != "" || regAuth["token"] != "")

	if hasAdHocCredentials {
		m.mu.Lock()
		m.jobs[id] = job
		m.persistJob(job)
		clone := cloneJob(job)
		m.mu.Unlock()

		log.Printf("jobs: scan %s queued locally (image=%s, ad-hoc registry credentials)", id, image)
		m.localQueue <- QueueItem{JobID: id, RegistryAuth: regAuth}
		return clone
	}

	m.mu.Lock()
	m.persistJob(job)
	m.mu.Unlock()

	log.Printf("jobs: scan %s queued (image=%s)", id, image)
	m.enqueueShared(id, now)
	return job
}

// IsLocal reports whether this process is the one running (or that has run)
// id - either because it was created here with ad-hoc credentials pinned to
// this pod, or because one of this pod's workers claimed it off the shared
// queue - meaning it's the pod that will Broadcast its events locally.
// Callers use this to decide whether streaming a job's live updates can
// subscribe to the local pub/sub channel or must instead poll the shared
// volume, since Broadcast never crosses pod boundaries and no other pod
// will ever receive an update for a job it isn't the one running.
func (m *Manager) IsLocal(id string) bool {
	m.mu.RLock()
	_, exists := m.jobs[id]
	m.mu.RUnlock()
	return exists
}

func (m *Manager) GetJob(id string) *Job {
	m.mu.RLock()
	job, exists := m.jobs[id]
	var clone *Job
	if exists {
		clone = cloneJob(job)
	}
	m.mu.RUnlock()
	if exists {
		return clone
	}
	return m.readFullJob(id)
}

// ListJobs enumerates scansDir on the shared volume rather than this
// process's in-memory jobs map, which only ever holds jobs this pod itself
// created (see IsLocal) - a multi-pod deployment's scan history spans every
// pod's writes, and the filesystem is the only place that union is visible.
// It reads each job's shallow job.json (no combined.log) so listing a large
// history doesn't mean loading every job's full log buffer into memory.
func (m *Manager) ListJobs() []JobSummary {
	entries, err := os.ReadDir(m.scansDir)
	if err != nil {
		return nil
	}

	list := make([]JobSummary, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if s := m.readJobSummary(e.Name()); s != nil {
			list = append(list, *s)
		}
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt > list[j].CreatedAt
	})
	if m.maxHistory > 0 && len(list) > m.maxHistory {
		list = list[:m.maxHistory]
	}
	return list
}

// readJobSummary reads just id's job.json (skipping combined.log, which
// JobSummary doesn't need) directly off disk.
func (m *Manager) readJobSummary(id string) *JobSummary {
	data, err := os.ReadFile(filepath.Join(m.scansDir, id, "job.json"))
	if err != nil {
		return nil
	}
	var job Job
	if err := json.Unmarshal(data, &job); err != nil {
		return nil
	}
	return &JobSummary{
		ID:         job.ID,
		Image:      job.Image,
		Status:     job.Status,
		CreatedAt:  job.CreatedAt,
		StartedAt:  job.StartedAt,
		FinishedAt: job.FinishedAt,
		Tools:      job.Tools,
		Summary:    job.Summary,
		Error:      job.Error,
	}
}

func (m *Manager) SetToolStatus(id, tool, status string, exitCode *int) {
	m.mu.Lock()
	job, exists := m.jobs[id]
	if !exists {
		m.mu.Unlock()
		return
	}
	now := time.Now().UnixMilli()
	tStatus := job.Tools[tool]
	if tStatus == nil {
		tStatus = &ToolStatus{}
		job.Tools[tool] = tStatus
	}
	tStatus.Status = status
	tStatus.ExitCode = exitCode
	switch status {
	case "running":
		tStatus.StartedAt = &now
	case "success", "failed", "error", "timeout":
		tStatus.FinishedAt = &now
	}
	m.persistJob(job)
	clone := cloneJob(job)
	m.mu.Unlock()

	m.Broadcast(id, Event{Type: eventTypeStatus, Data: clone})
}

// SetError records a fatal error for a job. Runners must call this instead
// of writing job.Error directly - direct writes aren't synchronized with
// m.mu and race with concurrent readers (HTTP handlers encoding the job).
func (m *Manager) SetError(id, msg string) {
	m.mu.Lock()
	job, exists := m.jobs[id]
	if !exists {
		m.mu.Unlock()
		return
	}
	job.Error = msg
	m.persistJob(job)
	clone := cloneJob(job)
	m.mu.Unlock()

	m.Broadcast(id, Event{Type: eventTypeStatus, Data: clone})
}

func (m *Manager) SetSummary(id string, updateFn func(s *Summary)) {
	m.mu.Lock()
	job, exists := m.jobs[id]
	if !exists {
		m.mu.Unlock()
		return
	}
	if job.Summary == nil {
		job.Summary = &Summary{}
	}
	updateFn(job.Summary)
	m.persistJob(job)
	clone := cloneJob(job)
	m.mu.Unlock()

	m.Broadcast(id, Event{Type: eventTypeStatus, Data: clone})
}

func (m *Manager) AppendLog(id, tool, stream, text string) {
	m.mu.Lock()
	job, exists := m.jobs[id]
	if !exists {
		m.mu.Unlock()
		return
	}
	entry := LogEntry{
		TS:     time.Now().UnixMilli(),
		Tool:   tool,
		Stream: stream,
		Text:   text,
	}
	job.Logs = append(job.Logs, entry)
	if len(job.Logs) > maxLogLines {
		job.Logs = job.Logs[1:]
	}

	logFile := filepath.Join(m.scansDir, id, "combined.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		data, _ := json.Marshal(entry)
		_, _ = f.Write(append(data, '\n'))
		_ = f.Close()
	}
	m.mu.Unlock()

	m.Broadcast(id, Event{Type: "log", Data: entry})
}

func (m *Manager) ArtifactPath(id, name string) string {
	return filepath.Join(m.scansDir, id, name)
}

func (m *Manager) Subscribe(id string) (chan Event, func()) {
	ch := make(chan Event, 100)
	m.subMu.Lock()
	m.subscribers[id] = append(m.subscribers[id], ch)
	m.subMu.Unlock()

	unsubscribe := func() {
		m.subMu.Lock()
		defer m.subMu.Unlock()
		subs := m.subscribers[id]
		for i, c := range subs {
			if c == ch {
				m.subscribers[id] = append(subs[:i], subs[i+1:]...)
				close(ch)
				break
			}
		}
	}
	return ch, unsubscribe
}

func (m *Manager) Broadcast(id string, evt Event) {
	m.subMu.RLock()
	defer m.subMu.RUnlock()
	for _, ch := range m.subscribers[id] {
		select {
		case ch <- evt:
		default:
		}
	}
}

// persistJob writes via a temp file + rename rather than directly
// (os.WriteFile truncates in place) so concurrent readers on other pods -
// ListJobs and the SSE disk-tail fallback now read this file directly off
// the shared volume, not just this process's memory - never observe a
// truncated or partially-written job.json. Rename within the same
// directory is atomic on any POSIX-compliant filesystem, including NFS.
func (m *Manager) persistJob(job *Job) {
	dir := filepath.Join(m.scansDir, job.ID)
	_ = os.MkdirAll(dir, 0755)

	// Save job.json without logs array
	shallow := *job
	shallow.Logs = nil
	data, _ := json.MarshalIndent(shallow, "", "  ")

	final := filepath.Join(dir, "job.json")
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return
	}
	_ = os.Rename(tmp, final)
}

func (m *Manager) readFullJob(id string) *Job {
	dir := filepath.Join(m.scansDir, id)
	jobData, err := os.ReadFile(filepath.Join(dir, "job.json"))
	if err != nil {
		return nil
	}
	var job Job
	if err := json.Unmarshal(jobData, &job); err != nil {
		return nil
	}

	// Read combined.log
	logFile := filepath.Join(dir, "combined.log")
	if lData, err := os.ReadFile(logFile); err == nil {
		lines := splitLines(lData)
		for _, line := range lines {
			if len(line) == 0 {
				continue
			}
			var entry LogEntry
			if err := json.Unmarshal(line, &entry); err == nil {
				job.Logs = append(job.Logs, entry)
			}
		}
		if len(job.Logs) > maxLogLines {
			job.Logs = job.Logs[len(job.Logs)-maxLogLines:]
		}
	}
	return &job
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
