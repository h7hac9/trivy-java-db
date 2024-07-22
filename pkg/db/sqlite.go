package db

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"golang.org/x/xerrors"
	"strings"
)

type Sqlite struct {
	client *sql.DB
	dir    string
}

func NewSqlite(dbPath string) (*Sqlite, error) {
	var err error

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, xerrors.Errorf("can't open db: %w", err)
	}

	if _, err := db.Exec("PRAGMA foreign_keys=true"); err != nil {
		return nil, xerrors.Errorf("failed to enable 'foreign_keys': %w", err)
	}

	return &Sqlite{client: db, dir: dbPath}, nil
}

func (sqlite *Sqlite) Init() error {
	if _, err := sqlite.client.Exec("CREATE TABLE artifacts(id INTEGER PRIMARY KEY, group_id TEXT, artifact_id TEXT)"); err != nil {
		return xerrors.Errorf("unable to create 'artifacts' table: %w", err)
	}
	if _, err := sqlite.client.Exec("CREATE TABLE indices(artifact_id INTEGER, version TEXT, sha1 BLOB, archive_type TEXT, foreign key (artifact_id) references artifacts(id))"); err != nil {
		return xerrors.Errorf("unable to create 'indices' table: %w", err)
	}

	if _, err := sqlite.client.Exec("CREATE UNIQUE INDEX artifacts_idx ON artifacts(artifact_id, group_id)"); err != nil {
		return xerrors.Errorf("unable to create 'artifacts_idx' index: %w", err)
	}
	if _, err := sqlite.client.Exec("CREATE INDEX indices_artifact_idx ON indices(artifact_id)"); err != nil {
		return xerrors.Errorf("unable to create 'indices_artifact_idx' index: %w", err)
	}
	if _, err := sqlite.client.Exec("CREATE UNIQUE INDEX indices_sha1_idx ON indices(sha1)"); err != nil {
		return xerrors.Errorf("unable to create 'indices_sha1_idx' index: %w", err)
	}
	return nil
}

func (sqlite *Sqlite) Dir() string {
	return sqlite.dir
}

func (sqlite *Sqlite) VacuumDB() error {
	if _, err := sqlite.client.Exec("VACUUM"); err != nil {
		return xerrors.Errorf("vacuum database error: %w", err)
	}
	return nil
}

func (sqlite *Sqlite) Close() error {
	return sqlite.client.Close()
}

//////////////////////////////////////
// functions to interaction with DB //
//////////////////////////////////////

func (sqlite *Sqlite) InsertIndexes(indexes []types.Index) error {
	if len(indexes) == 0 {
		return nil
	}
	tx, err := sqlite.client.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err = sqlite.insertArtifacts(tx, indexes); err != nil {
		return xerrors.Errorf("insert error: %w", err)
	}

	for _, index := range indexes {
		_, err = tx.Exec(`
			INSERT INTO indices(artifact_id, version, sha1, archive_type)
			VALUES (
			        (SELECT id FROM artifacts 
			            WHERE group_id=? AND artifact_id=?), 
			        ?, ?, ?
			) ON CONFLICT(sha1) DO NOTHING`,
			index.GroupID, index.ArtifactID, index.Version, index.SHA1, index.ArchiveType)
		if err != nil {
			return xerrors.Errorf("unable to insert to 'indices' table: %w", err)
		}
	}

	return tx.Commit()
}

func (sqlite *Sqlite) insertArtifacts(tx *sql.Tx, indexes []types.Index) error {
	query := `INSERT OR IGNORE INTO artifacts(group_id, artifact_id) VALUES `
	query += strings.Repeat("(?, ?), ", len(indexes))
	query = strings.TrimSuffix(query, ", ")

	var values []any
	for _, index := range indexes {
		values = append(values, index.GroupID, index.ArtifactID)
	}
	if _, err := tx.Exec(query, values...); err != nil {
		return xerrors.Errorf("unable to insert to 'artifacts' table: %w", err)
	}
	return nil
}

func (sqlite *Sqlite) SelectIndexBySha1(sha1 string) (types.Index, error) {
	var index types.Index
	sha1b, err := hex.DecodeString(sha1)
	if err != nil {
		return index, xerrors.Errorf("sha1 decode error: %w", err)
	}
	row := sqlite.client.QueryRow(`
		SELECT a.group_id, a.artifact_id, i.version, i.sha1, i.archive_type 
		FROM indices i
		JOIN artifacts a ON a.id = i.artifact_id
        WHERE i.sha1 = ?`,
		sha1b)
	err = row.Scan(&index.GroupID, &index.ArtifactID, &index.Version, &index.SHA1, &index.ArchiveType)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return index, xerrors.Errorf("select index error: %w", err)
	}
	return index, nil
}

func (sqlite *Sqlite) SelectIndexByArtifactIDAndGroupID(artifactID, groupID string) (types.Index, error) {
	var index types.Index
	row := sqlite.client.QueryRow(`
		SELECT a.group_id, a.artifact_id, i.version, i.sha1, i.archive_type
		FROM indices i 
		JOIN artifacts a ON a.id = i.artifact_id
        WHERE a.group_id = ? AND a.artifact_id = ?`,
		groupID, artifactID)
	err := row.Scan(&index.GroupID, &index.ArtifactID, &index.Version, &index.SHA1, &index.ArchiveType)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return index, xerrors.Errorf("select index error: %w", err)
	}
	return index, nil
}

// SelectIndexesByArtifactIDAndFileType returns all indexes for `artifactID` + `fileType` if `version` exists for them
func (sqlite *Sqlite) SelectIndexesByArtifactIDAndFileType(artifactID, version string, fileType types.ArchiveType) ([]types.Index, error) {
	var indexes []types.Index
	rows, err := sqlite.client.Query(`
		SELECT f_id.group_id, f_id.artifact_id, i.version, i.sha1, i.archive_type
		FROM indices i
		JOIN (SELECT a.id, a.group_id, a.artifact_id
      	      FROM indices i
        	  JOIN artifacts a on a.id = i.artifact_id
      	      WHERE a.artifact_id = ? AND i.version = ? AND i.archive_type = ?) f_id ON f_id.id = i.artifact_id`,
		artifactID, version, fileType)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, xerrors.Errorf("select indexes error: %w", err)
	}
	for rows.Next() {
		var index types.Index
		if err = rows.Scan(&index.GroupID, &index.ArtifactID, &index.Version, &index.SHA1, &index.ArchiveType); err != nil {
			return nil, xerrors.Errorf("scan row error: %w", err)
		}
		indexes = append(indexes, index)
	}
	return indexes, nil
}
