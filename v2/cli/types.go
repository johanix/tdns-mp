/*
 * Type aliases for types being migrated from tdns to tdns-mp.
 * These are currently aliases (= tdns.Foo) so both packages
 * use identical types. When the types are removed from tdns,
 * convert these to full struct definitions.
 */

package cli

import (
	tdns "github.com/johanix/tdns/v2"
)

// Combiner API types
type CombinerPost = tdns.CombinerPost
type CombinerResponse = tdns.CombinerResponse
type CombinerEditPost = tdns.CombinerEditPost
type CombinerEditResponse = tdns.CombinerEditResponse
type CombinerDebugPost = tdns.CombinerDebugPost
type CombinerDebugResponse = tdns.CombinerDebugResponse
