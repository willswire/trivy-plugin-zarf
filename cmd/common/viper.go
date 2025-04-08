package common

import (
	"fmt"
	"os"
)

//goland:noinspection GoCommentStart
const (
	VEnvPrefix         = "TRIVY_PLUGIN_ZARF"
	VDefaultConfigName = ".trivy_plugin_zarf"

	// Root config keys

	VConfig        = "config"
	VConfigLong    = "config"
	VConfigShort   = "c"
	VConfigDefault = ""
	VConfigUsage   = `Env: TRIVY_PLUGIN_ZARF_CONFIG
Optional config file (default $HOME/.trivy_plugin_zarf.yaml)`

	VLogLevel        = "log-level"
	VLogLevelLong    = "log-level"
	VLogLevelShort   = "l"
	VLogLevelDefault = "info"
	VLogLevelUsage   = `Env: TRIVY_PLUGIN_ZARF_LOG_LEVEL
CfgFile: log-level
Log level [debug, info, warn, error]`

	VLogFormat        = "log-format"
	VLogFormatLong    = "log-format"
	VLogFormatDefault = "console"
	VLogFormatUsage   = `Env: TRIVY_PLUGIN_ZARF_LOG_FORMAT
CfgFile: log-format
Log format [console, json, dev, none]`

	VNoColor        = "no-color"
	VNoColorLong    = "no-color"
	VNoColorDefault = false
	VNoColorUsage   = `Env: TRIVY_PLUGIN_ZARF_NO_COLOR
CfgFile: no-color
Disable colorized output`

	// Scan config keys

	VScanDbRepository        = "db-repository"
	VScanDbRepositoryLong    = "db-repository"
	VScanDbRepositoryDefault = "ghcr.io/aquasecurity/trivy-db"
	VScanDbRepositoryUsage   = `Env: TRIVY_PLUGIN_ZARF_SCAN_DB_REPOSITORY
CfgFile: scan.db-repository
Trivy DB repository to use (default ghcr.io/aquasecurity/trivy-db)`

	VScanOutput        = "output"
	VScanOutputLong    = "output"
	VScanOutputShort   = "o"
	VScanOutputDefault = ""
	VScanOutputUsage   = `Env: TRIVY_PLUGIN_ZARF_SCAN_OUTPUT
CfgFile: scan.output
Output directory for JSON scan results. If not specified, the results will be printed to stdout.`

	VScanSkipSignatureValidation        = "skip-signature-validation"
	VScanSkipSignatureValidationLong    = "skip-signature-validation"
	VScanSkipSignatureValidationDefault = false
	VScanSkipSignatureValidationUsage   = `Env: TRIVY_PLUGIN_ZARF_SCAN_SKIP_SIGNATURE_VALIDATION
CfgFile: scan.skip-signature-validation
Skip signature validation when pulling a zarf package from an OCI registry.`

	VScanArch        = "arch"
	VScanArchLong    = "arch"
	VScanArchShort   = "a"
	VScanArchDefault = ""
	VScanArchUsage   = `Env: TRIVY_PLUGIN_ZARF_SCAN_ARCH
CfgFile: scan.arch
Architecture to pull for OCI images. If not specified, the architecture of the host will be used.`
)

func ValidateConfig(configPath string) error {
	if configPath == "" {
		return fmt.Errorf("config path cannot be empty")
	}
	// Check if the file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", configPath)
	}

	return nil
}
