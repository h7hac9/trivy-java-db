package main

import (
	"context"
	"fmt"
	"github.com/h7hac9/trivy-java-db/pkg/types"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/h7hac9/trivy-java-db/pkg/builder"
	"github.com/h7hac9/trivy-java-db/pkg/crawler"
	"github.com/h7hac9/trivy-java-db/pkg/db"

	_ "modernc.org/sqlite"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("%+v", err)
	}
}

var (
	// Used for flags.
	cacheDir string
	limit    int

	// mysql config
	dbConnectURL string
	// sqlite config
	dbPath string

	rootCmd = &cobra.Command{
		Use:   "trivy-java-db",
		Short: "Build Java DB to store maven indexes",
	}
	crawlCmd = &cobra.Command{
		Use:   "crawl",
		Short: "Crawl maven indexes and save them into files",
		RunE: func(cmd *cobra.Command, args []string) error {
			return crawl(cmd.Context())
		},
	}
	buildCmd = &cobra.Command{
		Use:   "build",
		Short: "Build Java DB",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dbPath != "" {
				return build(&types.DBConfig{SqliteDBConfig: &types.SqliteDBConfig{DBPath: dbPath}})
			} else if dbConnectURL != "" {
				return build(&types.DBConfig{MysqlDBConfig: &types.MysqlDBConfig{DBConnectURL: dbConnectURL}})
			}
			return fmt.Errorf("must use --sqlite or --mysql")
		},
	}
)

func init() {
	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		log.Fatal(err)
	}

	rootCmd.PersistentFlags().StringVar(&cacheDir, "cache-dir", filepath.Join(userCacheDir, "trivy-java-db"),
		"cache dir")
	rootCmd.PersistentFlags().IntVar(&limit, "limit", 1000, "max parallelism")

	buildCmd.Flags().Bool("mysql", false, "use mysql db")
	buildCmd.Flags().StringVar(&dbConnectURL, "db-connect-url", "", "database connect url")
	buildCmd.MarkFlagsRequiredTogether("mysql", "db-connect-url")

	buildCmd.Flags().Bool("sqlite", false, "use sqlite db")
	buildCmd.Flags().StringVar(&dbPath, "db-path", "", "database path")
	buildCmd.MarkFlagsRequiredTogether("sqlite", "db-path")

	buildCmd.MarkFlagsMutuallyExclusive("mysql", "sqlite")

	rootCmd.AddCommand(crawlCmd)
	rootCmd.AddCommand(buildCmd)
}

func crawl(ctx context.Context) error {
	c := crawler.NewCrawler(crawler.Option{
		Limit:    int64(limit),
		CacheDir: cacheDir,
	})
	if err := c.Crawl(ctx); err != nil {
		return xerrors.Errorf("crawl error: %w", err)
	}
	return nil
}

func build(conf *types.DBConfig) error {
	if err := db.Reset(cacheDir); err != nil {
		return xerrors.Errorf("db reset error: %w", err)
	}
	dbDir := filepath.Join(cacheDir, "db")
	log.Printf("Database path: %s", dbDir)
	dbc, err := db.New(dbDir, conf)
	if err != nil {
		return xerrors.Errorf("db create error: %w", err)
	}
	if err = dbc.Init(); err != nil {
		return xerrors.Errorf("db init error: %w", err)
	}
	meta := db.NewMetadata(dbDir)
	b := builder.NewBuilder(dbc, meta)
	if err = b.Build(cacheDir); err != nil {
		return xerrors.Errorf("db build error: %w", err)
	}
	return nil
}
