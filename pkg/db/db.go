package db

import (
	"fmt"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"golang.org/x/xerrors"
	"os"
	"path/filepath"
)

const (
	dbFileName    = "trivy-java.db"
	SchemaVersion = 1
)

type DB interface {
	Init() error
	Close() error
	VacuumDB() error
	InsertIndexes(indexes []types.Index) error
	SelectIndexBySha1(sha1 string) (types.Index, error)
	SelectIndexByArtifactIDAndGroupID(artifactID, groupID string) (types.Index, error)
	SelectIndexesByArtifactIDAndFileType(artifactID, version string, fileType types.ArchiveType) ([]types.Index, error)
}

func path(cacheDir string) string {
	return filepath.Join(cacheDir, dbFileName)
}

func Reset(cacheDir string) error {
	return os.RemoveAll(path(cacheDir))
}

func New(cacheDir string, conf *types.DBConfig) (DB, error) {
	dbPath := path(cacheDir)
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		return nil, xerrors.Errorf("failed to mkdir: %w", err)
	}

	switch {
	case conf.SqliteDBConfig != nil:
		return NewSqlite(conf.SqliteDBConfig.DBPath)
	case conf.MysqlDBConfig != nil:
		return NewMysql(conf.MysqlDBConfig.DBConnectURL)
	default:
		return nil, fmt.Errorf("no db config found")
	}
}
