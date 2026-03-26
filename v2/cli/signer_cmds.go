/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"github.com/spf13/cobra"
)

// SignerCmd is the parent command for all signer operations.
var SignerCmd = &cobra.Command{
	Use:   "signer",
	Short: "Interact with the MP signer via API",
}
