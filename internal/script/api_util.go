package script

import (
	"encoding/hex"

	lua "github.com/yuin/gopher-lua"
)

func buildUtilTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	L.SetField(t, "hex", L.NewFunction(utilHex))
	L.SetField(t, "unhex", L.NewFunction(utilUnhex))
	return t
}

// utilHex: scry.util.hex(bytes) -> string (lowercase hex)
func utilHex(L *lua.LState) int {
	b := L.CheckString(1)
	L.Push(lua.LString(hex.EncodeToString([]byte(b))))
	return 1
}

// utilUnhex: scry.util.unhex(hex) -> bytes|nil, err?
func utilUnhex(L *lua.LState) int {
	s := L.CheckString(1)
	b, err := hex.DecodeString(s)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(b))
	L.Push(lua.LNil)
	return 2
}
