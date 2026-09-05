package db

// Package-level wrappers for dashboard user CRUD, mirroring accounts.go.

// ListUsers returns every dashboard user, ordered by username.
func ListUsers() ([]User, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	return dbInstance.ListUsers()
}

// GetUserByID returns one user by row id.
func GetUserByID(id int64) (*User, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	return dbInstance.GetUserByID(id)
}

// GetUserByUsername returns one user by username (used by the login path).
func GetUserByUsername(username string) (*User, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	return dbInstance.GetUserByUsername(username)
}

// CreateUser inserts a new user with a pre-computed bcrypt hash and role.
func CreateUser(username, passwordHash, role string) (int64, error) {
	if err := Init(); err != nil {
		return 0, err
	}
	return dbInstance.CreateUser(username, passwordHash, role)
}

// UpdateUserPassword replaces a user's bcrypt hash.
func UpdateUserPassword(id int64, passwordHash string) error {
	if err := Init(); err != nil {
		return err
	}
	return dbInstance.UpdateUserPassword(id, passwordHash)
}

// UpdateUserRole changes a user's role ("admin" or "viewer").
func UpdateUserRole(id int64, role string) error {
	if err := Init(); err != nil {
		return err
	}
	return dbInstance.UpdateUserRole(id, role)
}

// SetUserDisabled enables/disables a user (a disabled user cannot log in and
// existing sessions are rejected on the next request).
func SetUserDisabled(id int64, disabled bool) error {
	if err := Init(); err != nil {
		return err
	}
	return dbInstance.SetUserDisabled(id, disabled)
}

// TouchUserLogin records the last successful login time.
func TouchUserLogin(id int64) error {
	if err := Init(); err != nil {
		return err
	}
	return dbInstance.TouchUserLogin(id)
}

// DeleteUser removes a user by id.
func DeleteUser(id int64) error {
	if err := Init(); err != nil {
		return err
	}
	return dbInstance.DeleteUser(id)
}

// CountUsers returns the total number of dashboard users.
func CountUsers() (int, error) {
	if err := Init(); err != nil {
		return 0, err
	}
	return dbInstance.CountUsers()
}

// CountAdmins returns the number of enabled admin users (used to block removing
// the last admin, which would lock everyone out of user management).
func CountAdmins() (int, error) {
	if err := Init(); err != nil {
		return 0, err
	}
	return dbInstance.CountAdmins()
}
