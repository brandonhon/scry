package script

import (
	"log/slog"

	lua "github.com/yuin/gopher-lua"
)

func buildLogTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	L.SetField(t, "info", L.NewFunction(logInfo))
	L.SetField(t, "warn", L.NewFunction(logWarn))
	L.SetField(t, "error", L.NewFunction(logError))
	return t
}

func logInfo(L *lua.LState) int  { slog.Info(L.CheckString(1), "source", "script"); return 0 }

// logInfoDirect is a Go-callable alias used by the NSE shim so it can
// log without re-entering Lua.
func logInfoDirect(msg string) { slog.Info(msg, "source", "script.nse") }
func logWarn(L *lua.LState) int  { slog.Warn(L.CheckString(1), "source", "script"); return 0 }
func logError(L *lua.LState) int { slog.Error(L.CheckString(1), "source", "script"); return 0 }
