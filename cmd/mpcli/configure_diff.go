/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Configurator: diff preview + top-level confirmation.
 *
 * Substitution templates produce deterministic output where
 * most lines are stable and only a handful differ per re-run.
 * That makes a simple positional line-diff adequate: for each
 * line index, show the old line, the new line, or mark it
 * unchanged. Not a true LCS diff, but readable for the expected
 * shape of change.
 *
 * The confirmation gate is intentionally a single top-level
 * yes/no for all files. Per-file confirmation belongs to the
 * live-server gate (Phase 6), not here.
 */
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// fileChange is one pending rewrite queued up for confirmation.
type fileChange struct {
	path   string
	oldTxt string // "" if the file does not exist yet
	newTxt string
}

// changed reports whether the file's content is going to move.
// Identical content is a no-op and filtered out before preview.
func (c fileChange) changed() bool { return c.oldTxt != c.newTxt }

// previewDiff writes a human-readable diff for `c` to `w`. For
// new files, all lines are shown with a `+` marker. For modified
// files, unchanged lines get ` ` and differing lines get `-`/`+`.
func previewDiff(w io.Writer, c fileChange) {
	if c.oldTxt == "" {
		fmt.Fprintf(w, "\n--- %s (new file, %d lines) ---\n", c.path, lineCount(c.newTxt))
		for _, line := range splitLines(c.newTxt) {
			fmt.Fprintf(w, "+ %s\n", line)
		}
		return
	}

	oldLines := splitLines(c.oldTxt)
	newLines := splitLines(c.newTxt)
	fmt.Fprintf(w, "\n--- %s ---\n", c.path)

	n := len(oldLines)
	if len(newLines) > n {
		n = len(newLines)
	}
	for i := 0; i < n; i++ {
		var o, ne string
		if i < len(oldLines) {
			o = oldLines[i]
		}
		if i < len(newLines) {
			ne = newLines[i]
		}
		switch {
		case i >= len(oldLines):
			fmt.Fprintf(w, "+ %s\n", ne)
		case i >= len(newLines):
			fmt.Fprintf(w, "- %s\n", o)
		case o == ne:
			fmt.Fprintf(w, "  %s\n", o)
		default:
			fmt.Fprintf(w, "- %s\n", o)
			fmt.Fprintf(w, "+ %s\n", ne)
		}
	}
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

func lineCount(s string) int {
	return len(splitLines(s))
}

// confirmApply shows all pending changes, summarises them, and
// asks for a single top-level yes/no. Returns true iff the user
// typed "yes" (case-insensitive, exact).
//
// Anything other than "yes" — including "y", empty, EOF — is
// treated as no. The typed confirmation is deliberately strict:
// a stray newline must not commit config changes.
func confirmApply(w io.Writer, in *bufio.Reader, changes []fileChange) bool {
	pending := make([]fileChange, 0, len(changes))
	for _, c := range changes {
		if c.changed() {
			pending = append(pending, c)
		}
	}
	if len(pending) == 0 {
		fmt.Fprintln(w, "\nNo changes to apply.")
		return false
	}

	for _, c := range pending {
		previewDiff(w, c)
	}

	fmt.Fprintf(w, "\nApply %d file change(s)? Type 'yes' to confirm: ", len(pending))
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	return strings.TrimSpace(line) == "yes"
}

// applyChanges writes each pending change using atomicWrite.
// Returns the list of backup paths created (for reporting).
// On first error, earlier writes have already committed — there
// is no rollback. The atomic-per-file guarantee is only
// per-file; a partial apply mid-sequence leaves the earlier
// files changed. In practice this matters little because the
// user has seen the full diff and confirmed the intent.
func applyChanges(w io.Writer, changes []fileChange) ([]string, error) {
	var backups []string
	for _, c := range changes {
		if !c.changed() {
			continue
		}
		bak, err := atomicWrite(c.path, c.newTxt)
		if err != nil {
			return backups, err
		}
		if bak != "" {
			fmt.Fprintf(w, "  wrote %s (backup: %s)\n", c.path, bak)
			backups = append(backups, bak)
		} else {
			fmt.Fprintf(w, "  wrote %s (new)\n", c.path)
		}
	}
	return backups, nil
}

// stdinReader is a small helper so the command can share a
// Reader across interview and confirmation, avoiding double-
// buffering surprises.
func stdinReader() *bufio.Reader {
	return bufio.NewReader(os.Stdin)
}
