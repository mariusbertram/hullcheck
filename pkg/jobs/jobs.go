package jobs

import (
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
	mu          sync.RWMutex
	scansDir    string
	indexFile   string
	jobs        map[string]*Job
	subscribers map[string][]chan Event
	subMu       sync.RWMutex
	runner      func(job *Job, regAuth map[string]string)
	queue       chan QueueItem
	maxHistory  int
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
		indexFile:   filepath.Join(scansDir, "index.json"),
		jobs:        make(map[string]*Job),
		subscribers: make(map[string][]chan Event),
		queue:       make(chan QueueItem, 500),
		maxHistory:  maxHistory,
	}

	m.loadHistory()
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
				m.executeJobSafely(workerID, item)
			}
		}()
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
				m.persistIndex()
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
	m.persistIndex()
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
	m.persistIndex()
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
	m.persistIndex()
	clone := cloneJob(job)
	m.mu.Unlock()

	log.Printf("jobs: scan %s queued (image=%s)", id, image)
	m.queue <- QueueItem{JobID: id, RegistryAuth: regAuth}
	return clone
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

func (m *Manager) ListJobs() []JobSummary {
	m.mu.RLock()
	list := m.listJobsLocked()
	// listJobsLocked shares Tools/Summary pointers with the live jobs map;
	// clone them since the list escapes the lock here (unlike persistIndex,
	// which marshals while still holding it).
	for i := range list {
		list[i].Tools = cloneToolsMap(list[i].Tools)
		list[i].Summary = cloneSummary(list[i].Summary)
	}
	m.mu.RUnlock()
	return list
}

// listJobsLocked assumes the caller already holds m.mu (read or write).
func (m *Manager) listJobsLocked() []JobSummary {
	list := make([]JobSummary, 0, len(m.jobs))
	for _, j := range m.jobs {
		list = append(list, JobSummary{
			ID:         j.ID,
			Image:      j.Image,
			Status:     j.Status,
			CreatedAt:  j.CreatedAt,
			StartedAt:  j.StartedAt,
			FinishedAt: j.FinishedAt,
			Tools:      j.Tools,
			Summary:    j.Summary,
			Error:      j.Error,
		})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt > list[j].CreatedAt
	})
	return list
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

func (m *Manager) persistJob(job *Job) {
	dir := filepath.Join(m.scansDir, job.ID)
	_ = os.MkdirAll(dir, 0755)

	// Save job.json without logs array
	shallow := *job
	shallow.Logs = nil
	data, _ := json.MarshalIndent(shallow, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "job.json"), data, 0644)
}

// persistIndex assumes the caller already holds m.mu. The on-disk history is
// capped at maxHistory entries (oldest first, dropped) so DATA_DIR/scans
// doesn't grow the index file unboundedly; ListJobs itself is not capped.
func (m *Manager) persistIndex() {
	list := m.listJobsLocked()
	if m.maxHistory > 0 && len(list) > m.maxHistory {
		list = list[:m.maxHistory]
	}
	data, _ := json.MarshalIndent(list, "", "  ")
	_ = os.WriteFile(m.indexFile, data, 0644)
}

func (m *Manager) loadHistory() {
	data, err := os.ReadFile(m.indexFile)
	if err != nil {
		return
	}
	var summaries []JobSummary
	if err := json.Unmarshal(data, &summaries); err == nil {
		for _, s := range summaries {
			if full := m.readFullJob(s.ID); full != nil {
				m.jobs[full.ID] = full
			}
		}
	}
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
