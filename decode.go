package main

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/codecat/go-libs/log"
)

func decodeLog(path string) (*logInfo, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	ret := &logInfo{
		bitSize: 64,
	}

	// Prepare regular expressions
	rModule := regexp.MustCompile(`^([0-9A-F]{8,16})-([0-9A-F]{8,16}): (.*)`)
	rCrashAddress := regexp.MustCompile(`^\t=>Occured at address 0x([0-9A-F]{8,16})$`)
	rByteCode := regexp.MustCompile(`^([0-9A-F]{8,16}): (.*)$`)
	rByteCodeSub := regexp.MustCompile(`[0-9A-F]{2}`)

	// Need to remember some states
	inException := false
	inModules := false
	inByteCode := false

	// Go through the file line by line
	scanner := bufio.NewScanner(fh)
	scanner.Split(bufio.ScanLines)
	lineNumber := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNumber++

		if inModules {
			matches := rModule.FindStringSubmatch(line)
			if len(matches) != 4 {
				log.Warn("Unable to decode module at line %d", lineNumber)
				continue
			}

			if len(matches[1]) == 8 {
				ret.bitSize = 32
			}

			start, _ := strconv.ParseUint(matches[1], 16, 64)
			end, _ := strconv.ParseUint(matches[2], 16, 64)
			name := matches[3]

			ret.modules = append(ret.modules, &moduleInfo{
				start: start,
				end:   end,
				name:  name,
			})

		} else if inByteCode {
			if line == "" {
				inByteCode = false
				continue
			}

			matches := rByteCode.FindStringSubmatch(line)
			if len(matches) != 3 {
				log.Warn("Unable to get bytecode at line %d", lineNumber)
				continue
			}

			if ret.byteCodeStart == 0 {
				addr, _ := strconv.ParseUint(matches[1], 16, 64)
				ret.byteCodeStart = addr
			}

			matchBytes := rByteCodeSub.FindAllString(matches[2], -1)
			for _, bstr := range matchBytes {
				b, _ := strconv.ParseUint(bstr, 16, 8)
				ret.byteCode = append(ret.byteCode, byte(b))
			}

		} else if inException {
			if line == "Modules:" {
				inModules = true
				continue
			} else if line == "ByteCode:" {
				ret.byteCode = make([]byte, 0)
				inByteCode = true
				continue
			} else if rCrashAddress.MatchString(line) {
				matches := rCrashAddress.FindStringSubmatch(line)
				addr, _ := strconv.ParseUint(matches[1], 16, 64)
				ret.crashAddress = addr
				continue
			}

		} else {
			if line == "--- ExceptionWin32 catched ---" || strings.HasPrefix(line, "Win32 Exception : ") {
				inException = true
				continue
			}
		}
	}

	return ret, nil
}
