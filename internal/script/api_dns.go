package script

import (
	"net"

	lua "github.com/yuin/gopher-lua"
)

func buildDNSTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	L.SetField(t, "reverse", L.NewFunction(dnsReverse))
	L.SetField(t, "lookup", L.NewFunction(dnsLookup))
	return t
}

// dnsReverse: scry.dns.reverse(ip) -> string|nil, err?
func dnsReverse(L *lua.LState) int {
	ip := L.CheckString(1)
	names, err := net.DefaultResolver.LookupAddr(L.Context(), ip)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	if len(names) == 0 {
		L.Push(lua.LNil)
		L.Push(lua.LString("no PTR records"))
		return 2
	}
	L.Push(lua.LString(names[0]))
	L.Push(lua.LNil)
	return 2
}

// dnsLookup: scry.dns.lookup(host) -> {ips...}, err?
func dnsLookup(L *lua.LState) int {
	host := L.CheckString(1)
	ips, err := net.DefaultResolver.LookupIP(L.Context(), "ip", host)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	t := L.NewTable()
	for i, ip := range ips {
		L.RawSetInt(t, i+1, lua.LString(ip.String()))
	}
	L.Push(t)
	L.Push(lua.LNil)
	return 2
}
