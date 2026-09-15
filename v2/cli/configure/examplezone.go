/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * mpcli configure subpackage: the example zone's zone file.
 */
package configure

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ensureExampleZone writes the example zone's zone file if it is absent
// and reports whether it did. An existing file belongs to the operator
// and is left alone; when it no longer names this run's agent (or
// auditor) the combiner would serve a zone that leaves them out, so a
// warning says so.
func ensureExampleZone(cv CoordinatedValues, l fsLayout, w io.Writer) (bool, error) {
	path := l.exampleZoneFile()
	existing, err := ReadFileIfExists(path)
	if err != nil {
		return false, err
	}
	if existing != "" {
		for _, id := range []string{cv.Agent.Identity, cv.Auditor.Identity} {
			if id != "" && !strings.Contains(strings.ToLower(existing), strings.ToLower(id)) {
				fmt.Fprintf(w, "  WARNING: %s has no HSYNC3 record for %s; add one, or remove the file and re-run to regenerate it\n", path, id)
			}
		}
		return false, nil
	}

	content, err := renderExampleZone(cv, l)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return false, fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return false, fmt.Errorf("close %s: %w", path, err)
	}
	return true, nil
}
