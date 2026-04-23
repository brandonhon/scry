package output

import (
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/bhoneycutt/gscan/internal/portscan"
)

// jsonWriter emits one host per line (NDJSON). Designed for pipelines:
// `gscan ... -o json | jq ...`.
type jsonWriter struct {
	w    io.Writer
	opts Options
	enc  *json.Encoder
}

// jsonHost is the wire schema. Field names are frozen once a release goes
// out; additions only, never renames.
type jsonHost struct {
	Addr    string       `json:"addr"`
	Up      bool         `json:"up"`
	Started time.Time    `json:"started"`
	Elapsed string       `json:"elapsed"`
	Results []jsonResult `json:"results"`
}

type jsonResult struct {
	Port    uint16 `json:"port"`
	Proto   string `json:"proto"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
	RTT     string `json:"rtt"`
	Err     string `json:"err,omitempty"`
}

func (j *jsonWriter) Begin() error {
	j.enc = json.NewEncoder(j.w)
	return nil
}

func (j *jsonWriter) WriteHost(hr portscan.HostResult) error {
	rows := make([]portscan.Result, len(hr.Results))
	copy(rows, hr.Results)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Port < rows[j].Port })

	results := make([]jsonResult, 0, len(rows))
	for _, r := range rows {
		if !j.keepPort(r) {
			continue
		}
		item := jsonResult{
			Port:    r.Port,
			Proto:   "tcp",
			State:   r.State.String(),
			Service: Service(r.Port),
			RTT:     r.RTT.Round(time.Microsecond).String(),
		}
		if r.Err != nil {
			item.Err = r.Err.Error()
		}
		results = append(results, item)
	}

	h := jsonHost{
		Addr:    hr.Addr.String(),
		Up:      hr.Up(),
		Started: hr.Started.UTC(),
		Elapsed: hr.Elapsed.Round(time.Microsecond).String(),
		Results: results,
	}
	return j.enc.Encode(h)
}

func (j *jsonWriter) End() error { return nil }

func (j *jsonWriter) keepPort(r portscan.Result) bool {
	if r.State == portscan.StateOpen {
		return true
	}
	if j.opts.Verbose >= 1 && (r.State == portscan.StateClosed || r.State == portscan.StateFiltered) {
		return true
	}
	if j.opts.Verbose >= 2 && r.State == portscan.StateError {
		return true
	}
	return false
}
