package rospkg

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	mikrotikUpgradeBaseURL = "https://upgrade.mikrotik.com/routeros"
)

var (
	defaultPackages = newPackageStore(mikrotikUpgradeBaseURL, ".", http.DefaultClient)
	getLatestCache  map[string]string
	getLatestLock   *sync.RWMutex
	architectures   = []string{
		"arm64",
		"arm",
		"mipsbe",
		"mmips",
		"smips",
		"tile",
		"ppc",
		"powerpc",
		"x86_64",
		"x86",
	}
)

func init() {
	getLatestCache = make(map[string]string)
	getLatestLock = &sync.RWMutex{}
}

type PkgID struct {
	Name         string
	Version      string
	Architecture string
}

type packageEntry struct {
	data     []byte
	verified bool
}

type packageStore struct {
	baseURL string
	dir     string
	client  *http.Client
	mu      sync.Mutex
	cache   map[string]packageEntry
}

func newPackageStore(baseURL, dir string, client *http.Client) *packageStore {
	return &packageStore{
		baseURL: baseURL,
		dir:     dir,
		client:  client,
		cache:   make(map[string]packageEntry),
	}
}

func GetLatest(ver, branch string) (string, error) {
	str := fmt.Sprintf("NEWEST%s.%s", ver, branch)
	getLatestLock.RLock()
	c, ok := getLatestCache[str]
	getLatestLock.RUnlock()
	if ok {
		return c, nil
	}
	getLatestLock.Lock()
	defer getLatestLock.Unlock()
	resp, err := http.Get(fmt.Sprintf("%s/%s", mikrotikUpgradeBaseURL, str))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request returned: %s", resp.Status)
	}
	s, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	ss := strings.Split(string(s), " ")
	getLatestCache[str] = ss[0]
	return ss[0], nil
}

func GetPackage(pkg PkgID, verifySHA256 bool) ([]byte, error) {
	return defaultPackages.getPackage(pkg, verifySHA256)
}

func (s *packageStore) getPackage(pkg PkgID, verifySHA256 bool) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fname := packageFilename(pkg)
	entry, ok := s.cache[fname]
	if !ok {
		url := fmt.Sprintf("%s/%s/%s", s.baseURL, pkg.Version, fname)
		bb, err := s.loadFile(fname, url, "package")
		if err != nil {
			return nil, err
		}
		entry = packageEntry{data: bb}
	}
	if verifySHA256 && !entry.verified {
		if err := s.verifyPackage(pkg, fname, entry.data); err != nil {
			return nil, err
		}
		entry.verified = true
	}
	s.cache[fname] = entry
	return entry.data, nil
}

func (s *packageStore) verifyPackage(pkg PkgID, fname string, data []byte) error {
	checksumName := fname + ".sha256"
	checksumURL := fmt.Sprintf("%s/%s/%s", s.baseURL, pkg.Version, checksumName)
	checksum, err := s.loadFile(checksumName, checksumURL, "checksum")
	if err != nil {
		return err
	}
	expected, err := parseChecksum(checksum, fname)
	if err != nil {
		return fmt.Errorf("invalid checksum for %q: %w", fname, err)
	}
	actual := sha256.Sum256(data)
	if actual != expected {
		return fmt.Errorf("SHA-256 mismatch for %q: expected %x, got %x", fname, expected, actual)
	}
	log.Printf("verified SHA-256 for %q", fname)
	return nil
}

func parseChecksum(data []byte, fname string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	fields := strings.Fields(string(data))
	if len(fields) != 2 || fields[1] != fname {
		return digest, fmt.Errorf("expected one SHA-256 hash followed by %q", fname)
	}
	if len(fields[0]) != sha256.Size*2 {
		return digest, fmt.Errorf("expected a 64-character SHA-256 hash")
	}
	decoded, err := hex.DecodeString(fields[0])
	if err != nil {
		return digest, fmt.Errorf("invalid SHA-256 hash: %w", err)
	}
	copy(digest[:], decoded)
	return digest, nil
}

func (s *packageStore) loadFile(fname, url, kind string) ([]byte, error) {
	bb, found, err := readLocalFile(filepath.Join(s.dir, fname), kind)
	if err != nil {
		return nil, err
	}
	if found {
		log.Printf("using local %s %q (%d bytes)", kind, fname, len(bb))
		return bb, nil
	}
	log.Printf("downloading %s %q", kind, fname)
	resp, err := s.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error fetching %s %q: %w", kind, url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download of %s %q returned: %s", kind, url, resp.Status)
	}
	bb, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading %s %q: %w", kind, url, err)
	}
	log.Printf("downloaded %s %q (%d bytes)", kind, fname, len(bb))
	return bb, nil
}

func readLocalPackage(fname string) ([]byte, bool, error) {
	return readLocalFile(fname, "package")
}

func readLocalFile(fname, kind string) ([]byte, bool, error) {
	bb, err := os.ReadFile(fname)
	if err == nil {
		return bb, true, nil
	}
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("error reading local %s %q: %w", kind, fname, err)
}

func packageFilename(pkg PkgID) string {
	pname := stripArchitectures(pkg.Name)
	isV6Core := strings.HasPrefix(pkg.Version, "6.") && strings.Contains(pname, "routeros")
	architecture := pkg.Architecture
	// RouterOS 6 core archives use "powerpc"; extra packages use "ppc".
	if architecture == "powerpc" && !isV6Core {
		architecture = "ppc"
	}
	fname := fmt.Sprintf("%s-%s-%s.npk", pname, pkg.Version, architecture)
	// RouterOS 6 core packages put the architecture before the version; extra packages do not.
	if isV6Core {
		fname = fmt.Sprintf("%s-%s-%s.npk", pname, architecture, pkg.Version)
	}
	fname = strings.ReplaceAll(fname, "-x86_64.npk", ".npk") // x86 does not have a suffix
	return fname
}

func stripArchitectures(s string) string {
	for _, v := range architectures {
		s = strings.ReplaceAll(s, fmt.Sprintf("-%s", v), "")
	}
	return s
}
