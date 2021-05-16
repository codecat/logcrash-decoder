package main

type logInfo struct {
	bitSize int

	crashAddress uint64

	byteCodeStart uint64
	byteCode      []byte

	modules []*moduleInfo
}

func (li *logInfo) getModuleAt(addr uint64) *moduleInfo {
	for _, m := range li.modules {
		if addr >= m.start && addr < m.end {
			return m
		}
	}
	return nil
}
