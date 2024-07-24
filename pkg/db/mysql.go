package db

import (
	"database/sql"
	"encoding/hex"
	"errors"
	_ "github.com/go-sql-driver/mysql"
	"github.com/h7hac9/trivy-java-db/pkg/types"
	"golang.org/x/xerrors"
	"strings"
)

type Mysql struct {
	client *sql.DB
}

func NewMysql(dbConnectURL string) (*Mysql, error) {
	var err error
	db, err := sql.Open("mysql", dbConnectURL)
	if err != nil {
		return nil, xerrors.Errorf("can't open %s db: %w", dbConnectURL, err)
	}

	return &Mysql{client: db}, nil
}

func (mysql *Mysql) Init() error {
	if _, err := mysql.client.Exec("CREATE TABLE IF NOT EXISTS artifacts(id INTEGER AUTO_INCREMENT PRIMARY KEY, group_id varchar(255), artifact_id varchar(255), CONSTRAINT artifacts_idx UNIQUE (artifact_id, group_id)) engine=InnoDB DEFAULT charset=utf8"); err != nil {
		return xerrors.Errorf("failed to create 'artifacts' table: %w", err)
	}

	if _, err := mysql.client.Exec("CREATE TABLE IF NOT EXISTS indices(artifact_id INTEGER, version varchar(255), sha1 blob, archive_type varchar(255), foreign key (artifact_id) references artifacts(id), CONSTRAINT indices_sha1_idx UNIQUE (sha1(255)), INDEX indices_artifact_idx(artifact_id))engine=InnoDB DEFAULT charset=utf8"); err != nil {
		return xerrors.Errorf("failed to create 'artifacts' table: %w", err)
	}
	return nil
}

func (mysql *Mysql) Close() error {
	return mysql.client.Close()
}

func (mysql *Mysql) VacuumDB() error {
	return nil
}

func (mysql *Mysql) InsertIndexes(indexes []types.Index) error {
	if len(indexes) == 0 {
		return nil
	}
	tx, err := mysql.client.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err = mysql.insertArtifacts(tx, indexes); err != nil {
		return xerrors.Errorf("insert error: %w", err)
	}

	for _, index := range indexes {
		_, err = tx.Exec(`
			INSERT IGNORE INTO indices(artifact_id, version, sha1, archive_type)
			VALUES (
			        (SELECT id FROM artifacts 
			            WHERE group_id=? AND artifact_id=?), 
			        ?, ?, ?
			)`,
			index.GroupID, index.ArtifactID, index.Version, index.SHA1, index.ArchiveType)
		if err != nil {
			return xerrors.Errorf("unable to insert to 'indices' table: %w", err)
		}
	}

	return tx.Commit()
}

func (mysql *Mysql) insertArtifacts(tx *sql.Tx, indexes []types.Index) error {
	query := `INSERT IGNORE INTO artifacts(group_id, artifact_id) VALUES `
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

func (mysql *Mysql) SelectIndexBySha1(sha1 string) (types.Index, error) {
	var index types.Index
	sha1b, err := hex.DecodeString(sha1)
	if err != nil {
		return index, xerrors.Errorf("sha1 decode error: %w", err)
	}
	row := mysql.client.QueryRow(`
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

func (mysql *Mysql) SelectIndexByArtifactIDAndGroupID(artifactID, groupID string) (types.Index, error) {
	var index types.Index
	row := mysql.client.QueryRow(`
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
func (mysql *Mysql) SelectIndexesByArtifactIDAndFileType(artifactID, version string, fileType types.ArchiveType) ([]types.Index, error) {
	var indexes []types.Index
	rows, err := mysql.client.Query(`
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
