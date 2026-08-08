package scanner

import (
	"fmt"

	"github.com/anchore/go-logger"
	"github.com/mariusbertram/anchor-webui/pkg/jobs"
)

type jobLogger struct {
	jobsMgr *jobs.Manager
	jobID   string
	tool    string
}

func newJobLogger(mgr *jobs.Manager, jobID, tool string) logger.Logger {
	return &jobLogger{
		jobsMgr: mgr,
		jobID:   jobID,
		tool:    tool,
	}
}

func (l *jobLogger) Errorf(format string, args ...interface{}) {
	l.jobsMgr.AppendLog(l.jobID, l.tool, "stderr", fmt.Sprintf(format, args...))
}

func (l *jobLogger) Error(args ...interface{}) {
	l.jobsMgr.AppendLog(l.jobID, l.tool, "stderr", fmt.Sprint(args...))
}

func (l *jobLogger) Warnf(format string, args ...interface{}) {
	l.jobsMgr.AppendLog(l.jobID, l.tool, "stderr", fmt.Sprintf(format, args...))
}

func (l *jobLogger) Warn(args ...interface{}) {
	l.jobsMgr.AppendLog(l.jobID, l.tool, "stderr", fmt.Sprint(args...))
}

func (l *jobLogger) Infof(format string, args ...interface{}) {
	l.jobsMgr.AppendLog(l.jobID, l.tool, "info", fmt.Sprintf(format, args...))
}

func (l *jobLogger) Info(args ...interface{}) {
	l.jobsMgr.AppendLog(l.jobID, l.tool, "info", fmt.Sprint(args...))
}

// Debug/Trace are intentionally dropped, not forwarded to AppendLog: syft
// emits these per-file/per-cataloger-internal (e.g. "not a MachO binary" for
// every binary it inspects) - on a real image that's thousands of SSE events
// for a single scan, enough to freeze the browser tab rendering them. Info
// and above (the actual progress/result messages) still come through.
func (l *jobLogger) Debugf(format string, args ...interface{}) {}

func (l *jobLogger) Debug(args ...interface{}) {}

func (l *jobLogger) Tracef(format string, args ...interface{}) {}

func (l *jobLogger) Trace(args ...interface{}) {}

func (l *jobLogger) WithFields(fields ...any) logger.MessageLogger {
	return l
}

func (l *jobLogger) Nested(fields ...any) logger.Logger {
	return l
}
