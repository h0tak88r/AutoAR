package db

// Package-level wrappers for bug-bounty account CRUD, mirroring settings.go.

// ListBBPAccounts returns accounts for a platform ("" = all platforms).
func ListBBPAccounts(platform string) ([]BBPAccount, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	return dbInstance.ListBBPAccounts(platform)
}

// UpsertBBPAccount inserts or updates an account (keyed by platform+label).
func UpsertBBPAccount(a BBPAccount) (int64, error) {
	if err := Init(); err != nil {
		return 0, err
	}
	return dbInstance.UpsertBBPAccount(a)
}

// SetBBPAccountEnabled toggles an account's enabled flag.
func SetBBPAccountEnabled(id int64, enabled bool) error {
	if err := Init(); err != nil {
		return err
	}
	return dbInstance.SetBBPAccountEnabled(id, enabled)
}

// UpdateBBPAccountToken persists a refreshed token for an account.
func UpdateBBPAccountToken(id int64, token string) error {
	if err := Init(); err != nil {
		return err
	}
	return dbInstance.UpdateBBPAccountToken(id, token)
}

// DeleteBBPAccount removes an account by id.
func DeleteBBPAccount(id int64) error {
	if err := Init(); err != nil {
		return err
	}
	return dbInstance.DeleteBBPAccount(id)
}
