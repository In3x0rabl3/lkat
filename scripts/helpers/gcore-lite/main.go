package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type region struct {
	start uint64
	end   uint64
	perms string
}

func main() {
	prefix := flag.String("o", "core", "output file prefix")
	dumpAll := flag.Bool("a", false, "ignored compatibility flag")
	flag.Parse()
	_ = dumpAll

	if flag.NArg() == 0 {
		usage()
		os.Exit(2)
	}

	exitCode := 0
	for _, pidArg := range flag.Args() {
		pid, err := strconv.Atoi(pidArg)
		if err != nil || pid <= 0 {
			fmt.Fprintf(os.Stderr, "gcore: invalid pid %q\n", pidArg)
			exitCode = 1
			continue
		}
		out := fmt.Sprintf("%s.%d", *prefix, pid)
		if err := dumpProcess(pid, out); err != nil {
			fmt.Fprintf(os.Stderr, "gcore: failed to create %s: %v\n", out, err)
			exitCode = 1
		}
	}
	os.Exit(exitCode)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gcore [-a] [-o prefix] pid1 [pid2...pidN]")
}

func dumpProcess(pid int, outputPath string) error {
	maps, err := parseMaps(pid)
	if err != nil {
		return err
	}
	memPath := filepath.Join("/proc", strconv.Itoa(pid), "mem")
	mem, err := os.Open(memPath)
	if err != nil {
		return err
	}
	defer mem.Close()

	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()

	buf := make([]byte, 1024*1024)
	var wroteAny bool
	for _, r := range maps {
		if len(r.perms) == 0 || r.perms[0] != 'r' || r.end <= r.start {
			continue
		}
		length := r.end - r.start
		var off uint64
		for off < length {
			chunk := uint64(len(buf))
			remaining := length - off
			if remaining < chunk {
				chunk = remaining
			}
			n, readErr := mem.ReadAt(buf[:chunk], int64(r.start+off))
			if n > 0 {
				if _, err := out.Write(buf[:n]); err != nil {
					return err
				}
				wroteAny = true
			}
			if readErr != nil {
				// Unreadable pages are expected in some mappings.
				if errors.Is(readErr, io.EOF) {
					break
				}
				break
			}
			off += uint64(n)
		}
	}
	if !wroteAny {
		return errors.New("no readable memory mapped")
	}
	return nil
}

func parseMaps(pid int) ([]region, error) {
	path := filepath.Join("/proc", strconv.Itoa(pid), "maps")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var regions []region
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		parts := strings.Split(fields[0], "-")
		if len(parts) != 2 {
			continue
		}
		start, err1 := strconv.ParseUint(parts[0], 16, 64)
		end, err2 := strconv.ParseUint(parts[1], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		regions = append(regions, region{
			start: start,
			end:   end,
			perms: fields[1],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return regions, nil
}
