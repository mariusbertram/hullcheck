package jobs

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

const maxLogLines = 4000

// jobStatusFailed is the terminal Job.Status value for a scan that errored
// out (as opposed to a ToolStatus's own "failed" value, which reads the
// same but is set independently per tool).
const jobStatusFailed = "failed"

// toolStatusPending is a ToolStatus's initial state before a tool starts running.
const toolStatusPending = "pending"

// eventTypeStatus identifies a Broadcast Event carrying a Job status snapshot.
const eventTypeStatus = "status"

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

type QueueItem struct {
	JobID        string
	RegistryAuth map[string]string
}

type Event struct {
	Type string      `json:"type"` // "status", "log", "done"
	Data interface{} `json:"data"`
}

type Manager struct {
	mu       sync.RWMutex
	scansDir string
	// jobs holds only jobs this process itself queued via CreateJob - the
	// only ones its own worker pool will ever run and Broadcast events for.
	// A multi-pod deployment shares scansDir but not memory: every other
	// pod's jobs live only on disk as far as this process is concerned, so
	// GetJob/IsLocal treat presence here as "this pod owns it" and fall
	// back to disk for everything else (see GetJob).
	jobs        map[string]*Job
	subscribers map[string][]chan Event
	subMu       sync.RWMutex
	runner      func(job *Job, regAuth map[string]string)
	queue       chan QueueItem
	maxHistory  int
	activeWG    sync.WaitGroup
}

func NewManager(dataDir string) (*Manager, error) {
	scansDir := filepath.Join(dataDir, "scans")
	if err := os.MkdirAll(scansDir, 0755); err != nil {
		return nil, err
	}

	concurrency := envInt("MAX_CONCURRENCY", 2)
	maxHistory := envInt("MAX_HISTORY", 200)

	m := &Manager{
		scansDir:    scansDir,
		jobs:        make(map[string]*Job),
		subscribers: make(map[string][]chan Event),
		queue:       make(chan QueueItem, 500),
		maxHistory:  maxHistory,
	}

	go m.workerPool(concurrency)
	log.Printf("jobs: worker pool started (concurrency=%d, maxHistory=%d)", concurrency, maxHistory)

	return m, nil
}

func (m *Manager) SetRunner(fn func(job *Job, regAuth map[string]string)) {
	m.runner = fn
}

func (m *Manager) workerPool(concurrency int) {
	for i := 0; i < concurrency; i++ {
		workerID := i
		go func() {
			for item := range m.queue {
				m.activeWG.Add(1)
				m.executeJobSafely(workerID, item)
				m.activeWG.Done()
			}
		}()
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
		m.mu.Unlock()
		return
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
		job.Status = "completed"
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

	m.mu.Lock()
	m.jobs[id] = job
	_ = os.MkdirAll(filepath.Join(m.scansDir, id), 0755)
	m.persistJob(job)
	clone := cloneJob(job)
	m.mu.Unlock()

	log.Printf("jobs: scan %s queued (image=%s)", id, image)
	m.queue <- QueueItem{JobID: id, RegistryAuth: regAuth}
	return clone
}

// IsLocal reports whether this process queued id via CreateJob, meaning
// it's the pod that will run it and Broadcast its events locally. Callers
// use this to decide whether streaming a job's live updates can subscribe
// to the local pub/sub channel or must instead poll the shared volume,
// since Broadcast never crosses pod boundaries and no other pod will ever
// receive an update for a job it didn't create itself.
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
