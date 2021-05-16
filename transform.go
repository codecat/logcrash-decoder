package main

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/jpap/go-zydis"
)

func replaceExtension(fnm, new string) string {
	old := path.Ext(fnm)
	return fnm[:len(fnm)-len(old)] + new
}

func transformLog(path string) error {
	info, err := decodeLog(path)
	if err != nil {
		return fmt.Errorf("unable to decode log: %s", err)
	}

	crashModule := info.getModuleAt(info.crashAddress)

	// Input stream
	fhIn, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unable to make input stream: %s", err)
	}

	// Output stream
	fhOut, err := os.Create(replaceExtension(path, ".decoded.txt"))
	if err != nil {
		return fmt.Errorf("unable to make output stream: %s", err)
	}

	// Prepare regular expressions
	rAddress := regexp.MustCompile(`address 0x([0-9A-F]{8,16})`)
	rOpenplanet := regexp.MustCompile(`^.*: Openplanet.dll$`)

	// Go through the file line by line
	inException := false
	inByteCode := false
	handledByteCode := false

	scanner := bufio.NewScanner(fhIn)
	scanner.Split(bufio.ScanLines)
	lineNumber := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNumber++

		if inException {
			if inByteCode {
				if !handledByteCode {
					var decoder *zydis.Decoder
					if info.bitSize == 64 {
						decoder = zydis.NewDecoder(zydis.MachineMode64, zydis.AddressWidth64)
					} else {
						decoder = zydis.NewDecoder(zydis.MachineMode64, zydis.AddressWidth32)
					}

					formatter, _ := zydis.NewFormatter(zydis.FormatterStyleIntel)

					for offset := 64; offset < 128; {
						addr := info.byteCodeStart + uint64(offset)

						instr, err := decoder.Decode(info.byteCode[offset:])
						if err != nil {
							break
						}

						text, err := formatter.FormatInstruction(instr, addr)
						text = strings.Trim(text, "\x00")
						if err != nil {
							fmt.Fprintf(fhOut, "Unable to format instruction: %s\n", err.Error())
							break
						}

						fmt.Fprintf(fhOut, "\t+0x%X: %s", crashModule.offsetOf(addr), text)
						if addr == info.crashAddress {
							fhOut.WriteString("  <---- CRASHED HERE")
						}
						fhOut.WriteString("\n")

						offset += int(instr.Length)
					}
					handledByteCode = true
					continue
				} else if line == "" {
					inByteCode = false
				} else {
					continue
				}
			} else {
				if line == "ByteCode:" {
					inByteCode = true
				}
			}
		} else {
			if line == "--- ExceptionWin32 catched ---" {
				inException = true
			}
		}

		// Replace any code-related addresses to relative addresses
		line = rAddress.ReplaceAllStringFunc(line, func(part string) string {
			matches := rAddress.FindStringSubmatch(part)
			addr, _ := strconv.ParseUint(matches[1], 16, 64)

			mod := info.getModuleAt(addr)
			if mod != nil {
				return part + fmt.Sprintf(" (%s: +0x%X)", mod.name, mod.offsetOf(addr))
			}

			return part
		})

		// Add some exclamation marks if Openplanet is loaded
		if rOpenplanet.MatchString(line) {
			line = "\t! ! !    " + line
		}

		fmt.Fprintf(fhOut, "%s\n", line)
	}

	return nil
}
