package db

// Package-level wrappers for the bug-bounty program catalog.

func UpsertCatalogProgram(c CatalogProgram) (int64, error) {
	if err := Init(); err != nil {
		return 0, err
	}
	return dbInstance.UpsertCatalogProgram(c)
}

func ReplaceCatalogDomains(programID int64, domains []CatalogDomain) error {
	if err := Init(); err != nil {
		return err
	}
	return dbInstance.ReplaceCatalogDomains(programID, domains)
}

func ClearCatalogSource(source string) error {
	if err := Init(); err != nil {
		return err
	}
	return dbInstance.ClearCatalogSource(source)
}

func SearchCatalogByKeyword(q string, limit int) ([]CatalogProgram, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	return dbInstance.SearchCatalogByKeyword(q, limit)
}

func SearchCatalogByDomain(q string, limit int) ([]CatalogDomainMatch, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	return dbInstance.SearchCatalogByDomain(q, limit)
}

func CatalogCounts() (int, int, error) {
	if err := Init(); err != nil {
		return 0, 0, err
	}
	return dbInstance.CatalogCounts()
}
