// Package script embeds a Lua 5.1 runtime (gopher-lua) so users can
// write small probes that run against open ports. See ip-scanner-plan.md
// §7 for the design discussion.
//
// A script defines three globals:
//
//	description = "one-line summary shown in --help / --list-scripts"
//	ports       = {80, 443}        -- table of ports; or "any" for every port
//	function run(host, port)
//	  ...
//	  return "finding string"      -- or return nil, "reason"
//	end
//
// A fresh Lua state is created for each run, so scripts cannot leak
// state between invocations. The API surface is registered under the
// global `gscan` table; see api*.go for details.
package script

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

// Script is a compiled, metadata-parsed Lua script ready to run.
type Script struct {
	Name        string   // basename of the file, minus extension
	Path        string   // absolute path used to re-compile
	Description string   // from `description` global
	Ports       []uint16 // from `ports` table; empty + AnyPort false = no ports
	AnyPort     bool     // set when `ports = "any"`
	chunk       *lua.FunctionProto
}

// Matches reports whether this script should run against port.
func (s *Script) Matches(port uint16) bool {
	if s.AnyPort {
		return true
	}
	for _, p := range s.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// Finding is the result of one script run.
type Finding struct {
	Script string // Script.Name
	Output string // what run() returned
}

// Load reads and compiles a single script file, extracting metadata.
// It does not run the script's `run` function.
func Load(path string) (*Script, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("script %q: %w", path, err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("script %q: %w", path, err)
	}

	chunk, err := compile(abs, string(data))
	if err != nil {
		return nil, fmt.Errorf("script %q: %w", path, err)
	}

	s := &Script{
		Name:  strings.TrimSuffix(filepath.Base(abs), filepath.Ext(abs)),
		Path:  abs,
		chunk: chunk,
	}

	// Run the script once in a throwaway state to pull out metadata.
	L := lua.NewState(lua.Options{SkipOpenLibs: false})
	defer L.Close()
	registerAPI(L)

	if err := doChunk(L, chunk); err != nil {
		return nil, fmt.Errorf("script %q: load: %w", path, err)
	}
	if desc := L.GetGlobal("description"); desc.Type() == lua.LTString {
		s.Description = desc.String()
	}
	ports := L.GetGlobal("ports")
	switch v := ports.(type) {
	case lua.LString:
		if strings.EqualFold(string(v), "any") {
			s.AnyPort = true
		} else {
			return nil, fmt.Errorf("script %q: ports string must be \"any\", got %q", path, string(v))
		}
	case *lua.LTable:
		v.ForEach(func(_ lua.LValue, val lua.LValue) {
			if n, ok := val.(lua.LNumber); ok {
				p := int(n)
				if p >= 1 && p <= 65535 {
					s.Ports = append(s.Ports, uint16(p))
				}
			}
		})
	case *lua.LNilType:
		// fall through — scripts without ports match nothing by default
	default:
		return nil, fmt.Errorf("script %q: ports must be a table or \"any\"", path)
	}
	if fn := L.GetGlobal("run"); fn.Type() != lua.LTFunction {
		return nil, fmt.Errorf("script %q: missing `run` function", path)
	}
	return s, nil
}

// Engine runs a collection of scripts against (host, port) pairs.
type Engine struct {
	scripts []*Script
	timeout time.Duration
}

// NewEngine returns an Engine configured with a per-call timeout.
// timeout<=0 uses a 5s default.
func NewEngine(scripts []*Script, timeout time.Duration) *Engine {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Engine{scripts: scripts, timeout: timeout}
}

// Scripts returns the loaded scripts, in the order they were provided.
func (e *Engine) Scripts() []*Script { return e.scripts }

// RunAll invokes every script whose Matches(port) reports true, in order,
// returning the collected findings. Errors returned by a script are
// logged into the finding slice as "error: ..." so the caller can
// surface them in output rather than silently dropping them.
func (e *Engine) RunAll(ctx context.Context, host string, port uint16) []Finding {
	var out []Finding
	for _, s := range e.scripts {
		if !s.Matches(port) {
			continue
		}
		finding, err := e.runOne(ctx, s, host, port)
		if err != nil {
			out = append(out, Finding{Script: s.Name, Output: "error: " + err.Error()})
			continue
		}
		if finding != "" {
			out = append(out, Finding{Script: s.Name, Output: finding})
		}
	}
	return out
}

func (e *Engine) runOne(ctx context.Context, s *Script, host string, port uint16) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	L := lua.NewState(lua.Options{SkipOpenLibs: false})
	defer L.Close()
	L.SetContext(callCtx)
	registerAPI(L)

	if err := doChunk(L, s.chunk); err != nil {
		return "", err
	}
	fn := L.GetGlobal("run")
	if fn.Type() != lua.LTFunction {
		return "", errors.New("missing `run` function")
	}
	if err := L.CallByParam(lua.P{Fn: fn, NRet: 2, Protect: true},
		lua.LString(host), lua.LNumber(port)); err != nil {
		return "", err
	}
	// Collect two returns, Lua-style: value, err.
	r2 := L.Get(-1)
	r1 := L.Get(-2)
	L.Pop(2)

	if r2.Type() == lua.LTString && r2.String() != "" {
		return "", errors.New(r2.String())
	}
	if r1.Type() == lua.LTString && r1.String() != "" {
		return r1.String(), nil
	}
	return "", nil
}

// -- helpers ------------------------------------------------------------------

func compile(name, src string) (*lua.FunctionProto, error) {
	reader := strings.NewReader(src)
	chunk, err := parse.Parse(reader, name)
	if err != nil {
		return nil, err
	}
	return lua.Compile(chunk, name)
}

func doChunk(L *lua.LState, chunk *lua.FunctionProto) error {
	lfunc := L.NewFunctionFromProto(chunk)
	L.Push(lfunc)
	return L.PCall(0, lua.MultRet, nil)
}
