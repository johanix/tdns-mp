/*
 * Copyright (c) Johan Stenstam, <johani@johani.org>
 *
 * HsyncDB wraps *tdns.KeyDB so that tdns-mp can define its own
 * methods (HSYNC peer CRUD, sync tracking, schema init, etc.)
 * while retaining access to all core tdns KeyDB methods via
 * Go embedding / promotion.
 */
package tdnsmp

import (
	tdns "github.com/johanix/tdns/v2"
)

type HsyncDB struct {
	*tdns.KeyDB
}

func NewHsyncDB(kdb *tdns.KeyDB) *HsyncDB {
	if kdb == nil {
		return nil
	}
	return &HsyncDB{KeyDB: kdb}
}
