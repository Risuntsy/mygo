package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestRPM writes the RPM package of an app and has the system's rpm check
// its digests and read its fields, dependencies and files, which are those
// of the Debian package but the directories the system owns.
func TestRPM(t *testing.T) {
	for _, tool := range []string{"rpm", "rpm2archive"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("no " + tool + " to read the package")
		}
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"license": "MIT", "homepage": "https://example.com/note-pad"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &Config{
		root: root, Name: "云 Note's Pad", Slug: "note-pad", Version: "1.2.0-beta.1",
		FileAssociations: []FileAssociation{{Ext: []string{"npad"}, Name: "Note <Pad>"}},
	}
	c.Linux.Comment = "Take notes"
	c.Linux.Command = commandNames{"note-pad", "np"}
	c.Linux.Depends = []string{"libnotify4", "libfoo1"}
	c.Linux.Maintainer = "Jane Doe <jane@example.com>"
	stage := t.TempDir()
	for name, mode := range map[string]fs.FileMode{"note-pad": 0o755, "tool.sh": 0o700, "data/it's a file.txt": 0o600, "data/empty": 0o644} {
		p := filepath.Join(stage, name)
		content := []byte(name)
		if strings.HasSuffix(name, "empty") {
			content = nil
		}
		if os.MkdirAll(filepath.Dir(p), 0o755) != nil || os.WriteFile(p, content, mode) != nil {
			t.Fatal("cannot write " + name)
		}
	}
	if err := os.Symlink("data", filepath.Join(stage, "data-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := writeLinuxDesktop(c, stage, "note-pad"); err != nil {
		t.Fatal(err)
	}
	app, err := entryNames(stage)
	if err != nil {
		t.Fatal(err)
	}
	deb, err := writeDeb(c, stage, "note-pad", "arm64", app)
	if err != nil {
		t.Fatal(err)
	}
	rpm, err := writeRPM(c, stage, "note-pad", "arm64", app)
	if err != nil {
		t.Fatal(err)
	}
	if got := filepath.Base(rpm); got != "note-pad-1.2.0~beta.1-1.aarch64.rpm" {
		t.Errorf("package %s", got)
	}

	if out, err := exec.Command("rpm", "--checksig", "--nosignature", rpm).CombinedOutput(); err != nil {
		t.Fatalf("rpm --checksig: %v\n%s", err, out)
	}
	query := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("rpm", append([]string{"-qp"}, append(args, rpm)...)...).Output()
		if err != nil {
			t.Fatalf("rpm -qp %q: %v", args, err)
		}
		return string(out)
	}
	fields := query("--qf", "%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{LICENSE}|%{URL}|%{SUMMARY}|%{DESCRIPTION}|%{PACKAGER}|%{SOURCERPM}")
	if want := "note-pad|1.2.0~beta.1|1|aarch64|MIT|https://example.com/note-pad|Take notes|云 Note's Pad is a desktop application.|Jane Doe <jane@example.com>|note-pad-1.2.0~beta.1-1.src.rpm"; fields != want {
		t.Errorf("fields\n%s\nwant\n%s", fields, want)
	}
	var requires []string
	for r := range strings.Lines(query("--requires")) {
		if r = strings.TrimSpace(r); !strings.HasPrefix(r, "rpmlib(") {
			requires = append(requires, r)
		}
	}
	if want := []string{"gtk3", "webkit2gtk4.1", "libnotify"}; !slices.Equal(requires, want) {
		t.Errorf("requires %q, want %q", requires, want)
	}
	if provides := strings.TrimSpace(query("--provides")); provides != "note-pad = 1.2.0~beta.1-1" {
		t.Errorf("provides %q", provides)
	}

	// The files as rpm unpacks them.
	f, err := os.Open(rpm)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command("rpm2archive", "-")
	cmd.Stdin = f
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("rpm2archive: %v", err)
	}
	unpacked := map[string]string{}
	gz, err := gzip.NewReader(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		content, _ := io.ReadAll(tr)
		unpacked[strings.TrimSuffix(strings.TrimPrefix(hdr.Name, "./"), "/")] = tarEntry(hdr, content)
	}
	packaged := map[string]string{}
	debEntries(t, deb, "data.tar.gz", func(hdr *tar.Header, content []byte) {
		name := strings.TrimSuffix(strings.TrimPrefix(hdr.Name, "./"), "/")
		if hdr.Typeflag == tar.TypeDir && !strings.HasPrefix(name, "opt/note-pad") {
			return // the system's
		}
		packaged[name] = tarEntry(hdr, content)
	})
	if !maps.Equal(unpacked, packaged) {
		for _, name := range slices.Sorted(maps.Keys(maps.Collect(func(yield func(string, string) bool) {
			for k, v := range unpacked {
				yield(k, v)
			}
			for k, v := range packaged {
				yield(k, v)
			}
		}))) {
			if unpacked[name] != packaged[name] {
				t.Errorf("%s: the RPM package has %q, the Debian package %q", name, unpacked[name], packaged[name])
			}
		}
	}
}

// tarEntry describes an entry of an archive, by its type, mode and
// content.
func tarEntry(hdr *tar.Header, content []byte) string {
	switch hdr.Typeflag {
	case tar.TypeDir:
		return fmt.Sprintf("dir %o", hdr.Mode&0o7777)
	case tar.TypeSymlink:
		return "link " + hdr.Linkname
	}
	return fmt.Sprintf("file %o %s", hdr.Mode&0o7777, content)
}

// TestRPMVersion turns semantic versions into RPM ones that rpm sorts as
// semantic versioning does, with a rebuild of build metadata after its
// version.
func TestRPMVersion(t *testing.T) {
	if _, err := exec.LookPath("rpm"); err != nil {
		t.Skip("no rpm to compare versions")
	}
	ordered := []string{"1.1.9", "1.2.0-alpha", "1.2.0-alpha.1", "1.2.0-beta.2", "1.2.0-beta.11", "1.2.0-rc.1-x", "1.2.0", "v1.2.0+build.5", "1.2.1-rc.1"}
	var versions []string
	for _, v := range ordered {
		versions = append(versions, rpmVersion(v))
	}
	var lua strings.Builder
	for i := 1; i < len(versions); i++ {
		fmt.Fprintf(&lua, "print(rpm.vercmp(%q, %q) .. \" \")\n", versions[i-1], versions[i])
	}
	out, err := exec.Command("rpm", "--eval", "%{lua:"+lua.String()+"}").Output()
	if err != nil {
		t.Fatal(err)
	}
	for i, cmp := range strings.Fields(string(out)) {
		if cmp != "-1" {
			t.Errorf("rpm sorts %s (of %s) %s %s (of %s)", versions[i], ordered[i], map[string]string{"0": "as", "1": "after"}[cmp], versions[i+1], ordered[i+1])
		}
	}
}
