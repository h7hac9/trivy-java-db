package types

type SqliteDBConfig struct {
	DBPath string
}

type MysqlDBConfig struct {
	DBConnectURL string
}

type DBConfig struct {
	SqliteDBConfig *SqliteDBConfig
	MysqlDBConfig  *MysqlDBConfig
}
