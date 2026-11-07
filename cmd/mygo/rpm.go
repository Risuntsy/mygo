package main

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// rpmArch maps GOARCH to the architectures of RPM, with the number the
// lead of a package gives each.
var rpmArch = map[string]struct {
	name string
	num  int16
}{
	"amd64":   {"x86_64", 1},
	"arm64":   {"aarch64", 19},
	"386":     {"i686", 1},
	"arm":     {"armv7hl", 12},
	"riscv64": {"riscv64", 22},
}

// rpmPackages maps the Debian packages that apps commonly depend on to
// those of Fedora, by the Debian name without its "t64" suffix. A path
// names a program that several repositories package.
var rpmPackages = map[string]string{
	"libgtk-3-0":                 "gtk3",
	"libwebkit2gtk-4.1-0":        "webkit2gtk4.1",
	"libayatana-appindicator3-1": "libayatana-appindicator-gtk3",
	"libnotify4":                 "libnotify",
	"libsecret-1-0":              "libsecret",
	"libsoup-3.0-0":              "libsoup3",
	"libglib2.0-0":               "glib2",
	"libasound2":                 "alsa-lib",
	"libpulse0":                  "pulseaudio-libs",
	"libnss3":                    "nss",
	"libssl3":                    "openssl-libs",
	"libx11-6":                   "libX11",
	"libxtst6":                   "libXtst",
	"libvulkan1":                 "vulkan-loader",
	"libgl1":                     "libglvnd-glx",
	"libegl1":                    "libglvnd-egl",
	"gstreamer1.0-plugins-base":  "gstreamer1-plugins-base",
	"gstreamer1.0-plugins-good":  "gstreamer1-plugins-good",
	"gstreamer1.0-plugins-bad":   "gstreamer1-plugins-bad-free",
	"gstreamer1.0-plugins-ugly":  "gstreamer1-plugins-ugly-free",
	"gstreamer1.0-libav":         "gstreamer1-plugin-libav",
	"ffmpeg":                     "/usr/bin/ffmpeg", // ffmpeg-free of Fedora, ffmpeg of RPM Fusion
	"xdg-utils":                  "xdg-utils",
	"zenity":                     "zenity",
	"curl":                       "curl",
	"git":                        "git",
}

// rpmVersion turns a semantic version into an RPM one, which cannot hold
// hyphens: a pre-release follows a tilde, which sorts it before its
// release (1.2.0~beta.1 of 1.2.0-beta.1), with its own hyphens as
// periods. Build metadata keeps its plus, after which the version sorts
// after the one without it, as a rebuild.
func rpmVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	v, build, hasBuild := strings.Cut(v, "+")
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v = v[:i] + "~" + strings.ReplaceAll(v[i+1:], "-", ".")
	}
	if hasBuild {
		v += "+" + build
	}
	return v
}

// rpmRelease is the release of the packages, which a new version of the
// app starts over.
const rpmRelease = "1"

// writeRPM packages the Linux app in stage, the executable name and the
// files next to it, as an RPM package of linuxPackageFiles, for Fedora,
// RHEL and the distributions built on them. It owns /opt/<name> and the
// files, and leaves the directories they are in to the packages of the
// system, whose file triggers register its desktop entry, icons and MIME
// types, as the triggers of Debian do. It returns the package's path.
//
// The package is RPM's version 4 format, which rpm 4.6 and later read,
// with a gzip compressed cpio payload and SHA-256 digests, unsigned.
func writeRPM(c *Config, stage, name, goarch string, app []string) (string, error) {
	arch, ok := rpmArch[goarch]
	if !ok {
		return "", fmt.Errorf("no RPM architecture for %s", goarch)
	}
	files, err := linuxPackageFiles(c, stage, name, app)
	if err != nil {
		return "", err
	}
	// rpm looks files up in the header by binary search.
	slices.SortFunc(files, func(a, b linuxFile) int { return strings.Compare(a.path, b.path) })

	mtime := int32(time.Now().Unix())
	payload := &bytes.Buffer{}
	gz, _ := gzip.NewWriterLevel(payload, gzip.BestCompression)
	cpio := &cpioWriter{w: gz, mtime: mtime}
	var (
		sizes, mtimes, flags, devices, inodes, verify, dirIndexes []int32
		modes, rdevs                                              []int16
		digests, links, users, langs, basenames, dirnames         []string
		size                                                      int64
	)
	for i, f := range files {
		mode := f.mode | 0o100000
		var data []byte
		digest := ""
		switch {
		case f.dir:
			mode = f.mode | 0o40000
		case f.link != "":
			mode = f.mode | 0o120000
			data = []byte(f.link)
		default:
			data = f.data
			sum := sha256.Sum256(data)
			digest = hex.EncodeToString(sum[:])
		}
		size += int64(len(data))
		cpio.add("./"+f.path, int64(i+1), mode, data)

		dir := "/" + path.Dir(f.path) + "/"
		index := slices.Index(dirnames, dir)
		if index < 0 {
			index = len(dirnames)
			dirnames = append(dirnames, dir)
		}
		sizes = append(sizes, int32(len(data)))
		modes = append(modes, int16(uint16(mode)))
		rdevs = append(rdevs, 0)
		mtimes = append(mtimes, mtime)
		digests = append(digests, digest)
		links = append(links, f.link)
		flags = append(flags, 0)
		users = append(users, "root")
		devices = append(devices, 1)
		inodes = append(inodes, int32(i+1))
		langs = append(langs, "")
		verify = append(verify, -1)
		dirIndexes = append(dirIndexes, int32(index))
		basenames = append(basenames, path.Base(f.path))
	}
	cpioSize := cpio.close()
	if cpio.err != nil {
		return "", cpio.err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	if size > math.MaxInt32 || cpioSize > math.MaxInt32 {
		return "", fmt.Errorf("the app is too large for an RPM package")
	}

	version := rpmVersion(c.Version)
	summary := c.Linux.Comment
	if summary == "" {
		summary = c.Name
	}
	depends, unknown := c.Linux.dependsIn(rpmPackages)
	for _, dep := range unknown {
		warnf("Leaving %s out of the RPM package's dependencies: it is a Debian package with no Fedora package known for it", dep)
	}
	var requires []rpmDependency
	for _, dep := range depends {
		requires = append(requires, rpmDependency{name: dep})
	}
	// What rpm must support to install the package.
	const rpmlib, lessEqual, equal = 1 << 24, 0x2 | 0x8, 0x8
	requires = append(requires,
		rpmDependency{"rpmlib(CompressedFileNames)", "3.0.4-1", rpmlib | lessEqual},
		rpmDependency{"rpmlib(FileDigests)", "4.6.0-1", rpmlib | lessEqual},
		rpmDependency{"rpmlib(PayloadFilesHavePrefix)", "4.0-1", rpmlib | lessEqual},
	)
	if strings.Contains(version, "~") {
		requires = append(requires, rpmDependency{"rpmlib(TildeInVersions)", "4.10.0-1", rpmlib | lessEqual})
	}
	var requireNames, requireVersions []string
	var requireFlags []int32
	for _, r := range requires {
		requireNames, requireVersions, requireFlags = append(requireNames, r.name), append(requireVersions, r.version), append(requireFlags, r.flags)
	}

	payloadSum := sha256.Sum256(payload.Bytes())
	h := &rpmHeader{}
	h.strings(100, "C") // the locales of the I18NSTRINGs
	h.string(1000, name)
	h.string(1001, version)
	h.string(1002, rpmRelease)
	h.i18n(1004, summary)
	h.i18n(1005, c.Name+" is a desktop application.")
	h.int32s(1006, mtime)
	h.int32s(1009, int32(size))
	h.string(1014, archLicense(c))
	if m := strings.Join(strings.Fields(c.Linux.Maintainer), " "); m != "" {
		h.string(1015, m)
	}
	h.i18n(1016, "Unspecified")
	if u := archURL(c); u != "" {
		h.string(1020, u)
	}
	h.string(1021, "linux")
	h.string(1022, arch.name)
	h.int32s(1028, sizes...)
	h.int16s(1030, modes...)
	h.int16s(1033, rdevs...)
	h.int32s(1034, mtimes...)
	h.strings(1035, digests...)
	h.strings(1036, links...)
	h.int32s(1037, flags...)
	h.strings(1039, users...)
	h.strings(1040, users...)
	// The source package that rpm takes the package for a binary one by.
	h.string(1044, fmt.Sprintf("%s-%s-%s.src.rpm", name, version, rpmRelease))
	h.int32s(1045, verify...)
	h.strings(1047, name)
	h.int32s(1048, requireFlags...)
	h.strings(1049, requireNames...)
	h.strings(1050, requireVersions...)
	h.int32s(1095, devices...)
	h.int32s(1096, inodes...)
	h.strings(1097, langs...)
	h.int32s(1112, equal)
	h.strings(1113, version+"-"+rpmRelease)
	h.int32s(1116, dirIndexes...)
	h.strings(1117, basenames...)
	h.strings(1118, dirnames...)
	h.string(1124, "cpio")
	h.string(1125, "gzip")
	h.string(1126, "9")
	h.int32s(5011, 8) // SHA-256 file digests
	h.string(5062, "utf-8")
	h.strings(5092, hex.EncodeToString(payloadSum[:]))
	h.int32s(5093, 8)
	header := h.bytes(63)

	sha1Sum, sha256Sum := sha1.Sum(header), sha256.Sum256(header)
	whole := md5.New()
	whole.Write(header)
	whole.Write(payload.Bytes())
	sig := &rpmHeader{}
	sig.string(269, hex.EncodeToString(sha1Sum[:]))
	sig.string(273, hex.EncodeToString(sha256Sum[:]))
	sig.int32s(1000, int32(len(header)+payload.Len()))
	sig.bin(1004, whole.Sum(nil))
	sig.int32s(1007, int32(cpioSize))
	signature := sig.bytes(62)

	var b bytes.Buffer
	// The lead, which rpm reads past.
	lead := make([]byte, 96)
	copy(lead, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0})
	binary.BigEndian.PutUint16(lead[8:], uint16(arch.num))
	copy(lead[10:75], fmt.Sprintf("%s-%s-%s", name, version, rpmRelease))
	binary.BigEndian.PutUint16(lead[76:], 1) // Linux
	binary.BigEndian.PutUint16(lead[78:], 5) // a signature header follows
	b.Write(lead)
	b.Write(signature)
	b.Write(make([]byte, (8-len(signature)%8)%8))
	b.Write(header)
	b.Write(payload.Bytes())

	out := filepath.Join(stage, fmt.Sprintf("%s-%s-%s.%s.rpm", name, version, rpmRelease, arch.name))
	return out, os.WriteFile(out, b.Bytes(), 0o644)
}

// rpmDependency is a package, or a feature of rpm, that a package
// requires, with the version it needs, compared as its flags say.
type rpmDependency struct {
	name, version string
	flags         int32
}

// rpmHeader builds a header of an RPM package: its signature, or its main
// header, of tags of typed values.
type rpmHeader struct {
	entries []rpmEntry
}

type rpmEntry struct {
	tag, typ, count int32
	data            []byte
}

// The types of RPM's tags.
const (
	rpmInt16       = 3
	rpmInt32       = 4
	rpmString      = 6
	rpmBin         = 7
	rpmStringArray = 8
	rpmI18NString  = 9
)

func (h *rpmHeader) add(tag, typ int32, count int, data []byte) {
	h.entries = append(h.entries, rpmEntry{tag, typ, int32(count), data})
}

func (h *rpmHeader) string(tag int32, s string) { h.add(tag, rpmString, 1, append([]byte(s), 0)) }

func (h *rpmHeader) i18n(tag int32, s string) { h.add(tag, rpmI18NString, 1, append([]byte(s), 0)) }

func (h *rpmHeader) bin(tag int32, b []byte) { h.add(tag, rpmBin, len(b), b) }

func (h *rpmHeader) strings(tag int32, s ...string) {
	var b []byte
	for _, v := range s {
		b = append(append(b, v...), 0)
	}
	h.add(tag, rpmStringArray, len(s), b)
}

func (h *rpmHeader) int32s(tag int32, v ...int32) {
	var b []byte
	for _, n := range v {
		b = binary.BigEndian.AppendUint32(b, uint32(n))
	}
	h.add(tag, rpmInt32, len(v), b)
}

func (h *rpmHeader) int16s(tag int32, v ...int16) {
	var b []byte
	for _, n := range v {
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	}
	h.add(tag, rpmInt16, len(v), b)
}

// bytes encodes the header, its entries sorted by tag after the region of
// region, which says that they are all immutable: 62 for the signature,
// 63 for the main header.
func (h *rpmHeader) bytes(region int32) []byte {
	slices.SortFunc(h.entries, func(a, b rpmEntry) int { return int(a.tag - b.tag) })
	var data []byte
	var index []byte
	entry := func(tag, typ, offset, count int32) {
		for _, v := range []int32{tag, typ, offset, count} {
			index = binary.BigEndian.AppendUint32(index, uint32(v))
		}
	}
	for _, e := range h.entries {
		align := map[int32]int{rpmInt16: 2, rpmInt32: 4}[e.typ]
		for align > 0 && len(data)%align != 0 {
			data = append(data, 0)
		}
		entry(e.tag, e.typ, int32(len(data)), e.count)
		data = append(data, e.data...)
	}
	// The region's trailer, at the end of the data, points back over the
	// index of all the entries and the region's own.
	trailer := int32(len(data))
	n := int32(len(h.entries) + 1)
	for _, v := range []int32{region, rpmBin, -n * 16, 16} {
		data = binary.BigEndian.AppendUint32(data, uint32(v))
	}
	regionEntry := make([]byte, 0, 16)
	for _, v := range []int32{region, rpmBin, trailer, 16} {
		regionEntry = binary.BigEndian.AppendUint32(regionEntry, uint32(v))
	}
	b := []byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0}
	b = binary.BigEndian.AppendUint32(b, uint32(n))
	b = binary.BigEndian.AppendUint32(b, uint32(len(data)))
	b = append(b, regionEntry...)
	b = append(b, index...)
	return append(b, data...)
}

// cpioWriter writes the "newc" cpio archive of an RPM package's payload.
type cpioWriter struct {
	w     io.Writer
	mtime int32
	n     int64
	err   error
}

func (c *cpioWriter) write(b []byte) {
	if c.err != nil {
		return
	}
	var n int
	n, c.err = c.w.Write(b)
	c.n += int64(n)
}

// pad pads the archive to 4 bytes.
func (c *cpioWriter) pad() { c.write(make([]byte, (4-c.n%4)%4)) }

func (c *cpioWriter) add(name string, ino, mode int64, data []byte) {
	c.write(fmt.Appendf(nil, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		ino, mode, 0, 0, 1, uint32(c.mtime), len(data), 0, 0, 0, 0, len(name)+1, 0))
	c.write(append([]byte(name), 0))
	c.pad()
	c.write(data)
	c.pad()
}

// close ends the archive and returns its size.
func (c *cpioWriter) close() int64 {
	c.add("TRAILER!!!", 0, 0, nil)
	return c.n
}
