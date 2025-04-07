package cmd

import (
	"github.com/willswire/trivy-plugin-zarf/cmd/common"
	logger "github.com/willswire/trivy-plugin-zarf/pkg"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log/slog"
)

var rootCmd = NewRootCommand()

func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "trivy zarf",
		Short:             "Zarf plugin for Trivy",
		Long:              `The Zarf plugin for Trivy scans container images in Zarf packages.`,
		Args:              cobra.MaximumNArgs(1),
		SilenceUsage:      false,
		SilenceErrors:     false,
		PersistentPreRunE: preRun,
	}

	cmd.AddCommand(NewScanCommand())

	return cmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringP(common.VConfigLong, common.VConfigShort, common.VConfigDefault, common.VConfigUsage)
	err := viper.BindPFlag(common.VConfig, rootCmd.PersistentFlags().Lookup(common.VConfigLong))
	if err != nil {
		logger.Default().Error("Error binding flag to viper:", err)
		os.Exit(1)
	}

	rootCmd.PersistentFlags().StringP(common.VLogLevelLong, common.VLogLevelShort, common.VLogLevelDefault, common.VLogLevelUsage)
	err = viper.BindPFlag(common.VLogLevel, rootCmd.PersistentFlags().Lookup(common.VLogLevelLong))
	if err != nil {
		logger.Default().Error("Error binding flag to viper:", err)
		os.Exit(1)
	}

	rootCmd.PersistentFlags().String(common.VLogFormatLong, common.VLogFormatDefault, common.VLogFormatUsage)
	err = viper.BindPFlag(common.VLogFormat, rootCmd.PersistentFlags().Lookup(common.VLogFormatLong))
	if err != nil {
		logger.Default().Error("Error binding flag to viper:", err)
		os.Exit(1)
	}

	rootCmd.PersistentFlags().Bool(common.VNoColorLong, common.VNoColorDefault, common.VNoColorUsage)
	err = viper.BindPFlag(common.VNoColor, rootCmd.PersistentFlags().Lookup(common.VNoColorLong))
	if err != nil {
		logger.Default().Error("Error binding flag to viper:", err)
		os.Exit(1)
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.SetEnvPrefix(common.VEnvPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	configFile := viper.GetString(common.VConfig)
	if configFile != "" {
		err := common.ValidateConfig(configFile)
		if err != nil {
			logger.Default().Error("Error validating config file", "cfgFile", configFile, "err", err)
			os.Exit(1)
		}
		viper.SetConfigFile(configFile)
	} else {
		// Find home directory
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(common.VDefaultConfigName)
	}

	// If a config file is found, read it in.
	err := viper.ReadInConfig()
	if err == nil {
		logger.Default().Info("Using config file", "cfgFile", viper.ConfigFileUsed())
	} else if configFile == "" {
		logger.Default().Info("Not using a config file")
	} else {
		logger.Default().Error("Error reading config file", "err", err)
		logger.Default().Error("Use --help flag for more information")
		os.Exit(1)
	}
}

func preRun(cmd *cobra.Command, _ []string) error {
	l, err := setupLogger(
		viper.GetString(common.VLogLevel),
		viper.GetString(common.VLogFormat),
		!viper.GetBool(common.VNoColor),
	)
	if err != nil {
		return err
	}
	ctx := logger.WithContext(cmd.Context(), l)
	cmd.SetContext(ctx)
	return nil
}

func setupLogger(level string, format string, color bool) (*slog.Logger, error) {
	sLevel, err := logger.ParseLevel(level)
	if err != nil {
		return nil, err
	}

	cfg := logger.Config{
		Level:       sLevel,
		Format:      logger.Format(format),
		Destination: logger.DestinationDefault,
		Color:       logger.Color(color),
	}
	l, err := logger.New(cfg)
	if err != nil {
		return nil, err
	}
	logger.SetDefault(l)
	l.Debug("logger successfully initialized", "cfg", cfg)
	return l, nil
}
