/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor web-user management CLI commands. The CLI:
 *   1. Asks the running auditor for the path to its users file
 *      (via "userdb-path" on /api/v1/auditor).
 *   2. Reads, mutates, and atomically rewrites the YAML file
 *      directly — bcrypt runs in the CLI, never in the auditor.
 *   3. Reminds the operator to run "auditor web user reload" so
 *      the running auditor swaps its in-memory user map.
 *
 * Why split file I/O between CLI and auditor: avoids any chicken-
 * and-egg issue when no users exist yet (the auditor refuses to
 * start without users; the CLI must therefore be able to create the
 * first user without contacting the auditor at all — though we
 * still ask for the path via the API rather than re-parsing the
 * auditor config from disk).
 */
package cli

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	tdnsmp "github.com/johanix/tdns-mp/v2"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var auditorWebCmd = &cobra.Command{
	Use:   "web",
	Short: "Auditor web-dashboard commands",
}

var auditorWebUserCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage web dashboard users",
}

var auditorWebUserListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured web dashboard users",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		path, err := fetchUsersFilePath()
		if err != nil {
			log.Fatal(err)
		}
		users, err := tdnsmp.ReadAuditWebUsersFile(path)
		if err != nil {
			log.Fatal(err)
		}
		if len(users) == 0 {
			fmt.Println("No users configured")
			return
		}
		fmt.Printf("%-32s\n", "Name")
		fmt.Println(strings.Repeat("-", 32))
		for _, u := range users {
			fmt.Println(u.Name)
		}
	},
}

var auditorWebUserCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new web dashboard user (prompts for password)",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		name, _ := cmd.Flags().GetString("name")
		if name == "" {
			log.Fatal("--name is required")
		}
		path, err := fetchUsersFilePath()
		if err != nil {
			log.Fatal(err)
		}
		users, err := tdnsmp.ReadAuditWebUsersFile(path)
		if err != nil {
			log.Fatal(err)
		}
		for _, u := range users {
			if u.Name == name {
				log.Fatalf("user %q already exists", name)
			}
		}
		password, err := promptNewPassword()
		if err != nil {
			log.Fatal(err)
		}
		hash, err := tdnsmp.HashPassword(password)
		if err != nil {
			log.Fatalf("hash password: %v", err)
		}
		users = append(users, AuditWebUser{Name: name, PasswordHash: hash})
		if err := tdnsmp.WriteAuditWebUsersFile(path, users); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("User %q created in %s.\n", name, path)
		fmt.Println("Run 'mpcli auditor web user reload' to apply to the running auditor.")
	},
}

var auditorWebUserDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a web dashboard user",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		name, _ := cmd.Flags().GetString("name")
		if name == "" {
			log.Fatal("--name is required")
		}
		path, err := fetchUsersFilePath()
		if err != nil {
			log.Fatal(err)
		}
		users, err := tdnsmp.ReadAuditWebUsersFile(path)
		if err != nil {
			log.Fatal(err)
		}
		out := make([]AuditWebUser, 0, len(users))
		removed := false
		for _, u := range users {
			if u.Name == name {
				removed = true
				continue
			}
			out = append(out, u)
		}
		if !removed {
			log.Fatalf("user %q not found", name)
		}
		if err := tdnsmp.WriteAuditWebUsersFile(path, out); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("User %q deleted from %s.\n", name, path)
		fmt.Println("Run 'mpcli auditor web user reload' to apply to the running auditor.")
	},
}

var auditorWebUserReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Tell the running auditor to re-read its users file",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := callAuditor(AuditPost{Command: "userdb-reload"})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(resp.Msg)
	},
}

// fetchUsersFilePath asks the running auditor for the configured
// users-file path. The CLI does not parse the auditor's own config
// file directly.
func fetchUsersFilePath() (string, error) {
	resp, err := callAuditor(AuditPost{Command: "userdb-path"})
	if err != nil {
		return "", err
	}
	if resp.UsersFile == "" {
		return "", errors.New("auditor reports no users_file configured (audit.web.auth.users_file)")
	}
	return resp.UsersFile, nil
}

// promptNewPassword reads a password twice from the terminal,
// without echo, and confirms they match.
func promptNewPassword() (string, error) {
	if !term.IsTerminal(int(syscall.Stdin)) {
		return "", errors.New("password prompt requires a terminal (no piped stdin)")
	}
	fmt.Fprint(os.Stderr, "Password: ")
	first, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if len(first) == 0 {
		return "", errors.New("password is empty")
	}
	fmt.Fprint(os.Stderr, "Confirm:  ")
	second, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if string(first) != string(second) {
		return "", errors.New("passwords do not match")
	}
	return string(first), nil
}

func init() {
	auditorWebUserCreateCmd.Flags().String("name", "", "username (required)")
	auditorWebUserDeleteCmd.Flags().String("name", "", "username (required)")

	auditorWebUserCmd.AddCommand(
		auditorWebUserListCmd,
		auditorWebUserCreateCmd,
		auditorWebUserDeleteCmd,
		auditorWebUserReloadCmd,
	)
	auditorWebCmd.AddCommand(auditorWebUserCmd)
	AuditorCmd.AddCommand(auditorWebCmd)
}
