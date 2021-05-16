package main

type moduleInfo struct {
	start uint64
	end   uint64
	name  string
}

func (mi *moduleInfo) offsetOf(addr uint64) uint64 {
	return addr - mi.start
}
