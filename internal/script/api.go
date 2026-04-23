package script

import (
	lua "github.com/yuin/gopher-lua"
)

// registerAPI installs the `gscan` table and its submodules onto L.
// Every call to runOne opens a fresh state, so this is the single
// entry point for API surface.
func registerAPI(L *lua.LState) {
	root := L.NewTable()

	L.SetField(root, "tcp", buildTCPTable(L))
	L.SetField(root, "tls", buildTLSTable(L))
	L.SetField(root, "dns", buildDNSTable(L))
	L.SetField(root, "log", buildLogTable(L))
	L.SetField(root, "util", buildUtilTable(L))

	L.SetGlobal("gscan", root)
}

// optTable is a small helper: pulls a numeric value out of a table
// (typically the opts argument to an API call), returning def when
// missing or non-numeric.
func optInt(tbl *lua.LTable, key string, def int) int {
	if tbl == nil {
		return def
	}
	v := tbl.RawGetString(key)
	if n, ok := v.(lua.LNumber); ok {
		return int(n)
	}
	return def
}

func optBool(tbl *lua.LTable, key string, def bool) bool {
	if tbl == nil {
		return def
	}
	v := tbl.RawGetString(key)
	if b, ok := v.(lua.LBool); ok {
		return bool(b)
	}
	return def
}

// checkOptsTable returns the optional opts table passed as arg index
// (or nil if absent / not a table). Scripts pass opts as the final arg.
func checkOptsTable(L *lua.LState, idx int) *lua.LTable {
	if L.GetTop() < idx {
		return nil
	}
	v := L.Get(idx)
	if t, ok := v.(*lua.LTable); ok {
		return t
	}
	return nil
}
