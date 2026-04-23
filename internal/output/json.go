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
	Addr      string         `json:"addr"`
	Hostname  string         `json:"hostname,omitempty"`
	Up        bool           `json:"up"`
	Started   time.Time      `json:"started"`
	Elapsed   string         `json:"elapsed"`
	Discovery *jsonDiscovery `json:"discovery,omitempty"`
	Results   []jsonResult   `json:"results"`
}

type jsonDiscovery struct {
	Via string `json:"via,omitempty"`
	RTT string `json:"rtt"`
}

type jsonResult struct {
	Port    uint16 `json:"port"`
	Proto   string `json:"proto"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
	RTT     string `json:"rtt"`
	Banner  string `json:"banner,omitempty"`
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
			Banner:  r.Banner,
		}
		if r.Err != nil {
			item.Err = r.Err.Error()
		}
		results = append(results, item)
	}

	h := jsonHost{
		Addr:     hr.Addr.String(),
		Hostname: hr.Hostname,
		Up:       hr.Up(),
		Started:  hr.Started.UTC(),
		Elapsed:  hr.Elapsed.Round(time.Microsecond).String(),
		Results:  results,
	}
	if hr.Discovery != nil {
		h.Discovery = &jsonDiscovery{
			Via: hr.Discovery.Via,
			RTT: hr.Discovery.RTT.Round(time.Microsecond).String(),
		}
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
