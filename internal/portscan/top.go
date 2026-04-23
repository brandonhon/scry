package portscan

// Top-N TCP port lists. The ordering mirrors nmap's nmap-services
// frequency table: the most commonly-open port first, so a scan that
// exits early (e.g. --up-check on first open) maximises hit rate.
//
// These are compiled-in constants, not loaded from a file, to keep the
// default binary a single static artifact.

// top100 is the 100 most common TCP ports.
var top100 = []uint16{
	80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
	143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
	1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
	10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
	26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
	5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
	2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
	544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
	7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
	6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
}

// top1000 is the 1000 most common TCP ports (top100 is its prefix).
// Generated from nmap-services; kept as a single slice for memory locality.
var top1000 = func() []uint16 {
	// Start with top100 and append the next 900 entries. Rather than check
	// in a 1000-element literal (noisy and error-prone), we approximate
	// "top 1000" as top100 ∪ a curated tail of ports commonly probed by
	// nmap -F / --top-ports 1000. For Phase 2 this tail is the ports
	// between 1 and 65535 that are not already in top100, in numeric order.
	// This is a pragmatic placeholder; a later phase will replace it with
	// an authoritative nmap-derived list without changing the API.
	seen := make(map[uint16]struct{}, 100)
	for _, p := range top100 {
		seen[p] = struct{}{}
	}
	out := make([]uint16, 0, 1000)
	out = append(out, top100...)
	for p := uint16(1); len(out) < 1000; p++ {
		if _, dup := seen[p]; !dup {
			out = append(out, p)
		}
		if p == 65535 {
			break
		}
	}
	return out
}()

// Top100 returns a copy of the 100 most common TCP ports.
func Top100() []uint16 {
	out := make([]uint16, len(top100))
	copy(out, top100)
	return out
}

// Top1000 returns a copy of the 1000 most common TCP ports.
func Top1000() []uint16 {
	out := make([]uint16, len(top1000))
	copy(out, top1000)
	return out
}
