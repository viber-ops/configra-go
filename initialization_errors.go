package configra

import (
	"errors"
	"fmt"
	"os"
)

// Diagnostics contain trusted field names and guidance, never supplied values,
// PEM decoder output, secret file contents, or paths from the operating system.
type initializationError struct {
	field, problem, hint, source string
}

func (err *initializationError) Error() string {
	field := err.field
	if names, ok := initializationFields[field]; ok {
		switch err.source {
		case "environment":
			field = names[1]
		case "file": // Keep the YAML field name.
		default:
			field = names[0]
		}
	}
	return fmt.Sprintf("Configra %s: %s. %s", field, err.problem, err.hint)
}

var initializationFields = map[string][2]string{
	"url":               {"BaseURL", "CONFIGRA_URL"},
	"token":             {"Token", "CONFIGRA_TOKEN / CONFIGRA_TOKEN_FILE"},
	"token_file":        {"TokenFile", "CONFIGRA_TOKEN_FILE"},
	"cert_file":         {"ClientCertificateFile", "CONFIGRA_CLIENT_CERT"},
	"key_file":          {"ClientKeyFile", "CONFIGRA_CLIENT_KEY"},
	"server_ca_file":    {"ServerCAFile", "CONFIGRA_SERVER_CA"},
	"timeout":           {"Timeout", "CONFIGRA_TIMEOUT"},
	"max_content_bytes": {"MaxContentBytes", "max_content_bytes"},
	"tls_config":        {"TLSConfig", "TLSConfig"},
}

func invalidInitialization(field, problem, hint string) error {
	return &initializationError{field: field, problem: problem, hint: hint}
}

func initializationSource(err error, source string) error {
	var configuration *initializationError
	if !errors.As(err, &configuration) {
		return err
	}
	copy := *configuration
	copy.source = source
	return &copy
}

func credentialReadError(field string, err error) error {
	problem := "cannot read the file or it exceeds the documented size limit"
	if errors.Is(err, os.ErrNotExist) {
		problem = "file was not found"
	}
	if errors.Is(err, os.ErrPermission) {
		problem = "file is not readable"
	}
	return invalidInitialization(field, problem, "Check the file path, Secret mount and read permissions; YAML-relative paths start next to the settings file.")
}
