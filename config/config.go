/*
 * Copyright (C) 2025 by John J. Rushford jrushford@apache.org
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// Package config handles the parsing and validation of TrueNAS certificate deployment configurations.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/ncruces/go-strftime"
	"gopkg.in/ini.v1"
)

const (
	Config_file             = "tnas-cert.ini"
	Default_base_cert_name  = "tnas-cert-deploy"
	Default_section         = "deploy_default"
	Default_port            = 443
	Default_protocol        = "wss"
	Default_timeout_seconds = 10
)

type Config struct {
	ApiKey              string `ini:"api_key"`                                            // TrueNAS 64 byte API Key
	CertBasename        string `ini:"cert_basename" validate:"required"`                  // Basename for cert naming in TrueNAS
	ClientApi           string `ini:"client_api" validate:"required,oneof=wsapi restapi"` // Client type, 'wsapi' (default) or restapi
	ConnectHost         string `ini:"connect_host" validate:"required,hostname|fqdn|ip"`  // TrueNAS hostname
	DeleteOldCerts      bool   `ini:"delete_old_certs"`                                   // Whether to remove old certificates
	StrictBasenameMatch bool   `ini:"strict_basename_match"`                              // Whether to use a strict basename match when deleting certs
	FullChainPath       string `ini:"full_chain_path" validate:"required"`                // Path to full_chain.pem
	Port                uint64 `ini:"port" validate:"min=1,max=65535"`                    // TrueNAS API endpoint port
	Protocol            string `ini:"protocol" validate:"oneof=ws wss http https"`        // Websocket/REST protocol
	PrivateKeyPath      string `ini:"private_key_path" validate:"required"`               // Path to private_key.pem
	TlsSkipVerify       bool   `ini:"tls_skip_verify"`                                    // Strict SSL cert verification of the endpoint
	AddAsUiCertificate  bool   `ini:"add_as_ui_certificate"`                              // Install as the active UI certificate if true
	AddAsFTPCertificate bool   `ini:"add_as_ftp_certificate"`                             // Install as the active FTP service certificate if true
	AddAsAppCertificate bool   `ini:"add_as_app_certificate"`                             // Install as the active APP service certificate if true
	// Note: AppList could be defined as a slice (Applist []string) and ini.v1 will automatically convert the comma-separated values
	AppList        string `ini:"app_list"`                                  // Comma separated list of Apps to deploy the certificate too.
	TimeoutSeconds int64  `ini:"timeout_seconds" validate:"required,min=1"` // The number of seconds after which the truenas client calls fail
	Debug          bool   `ini:"debug"`                                     // Debug logging if true
	Username       string `ini:"username"`                                  // An admin user name for the TrueNAS target
	Password       string `ini:"password"`                                  // The TrueNAS target Admin user's password

	certName  string // instance generated certificate name.
	serverURL string // instance generated server URL
}

// LoadConfig loads configuration settings from the configuration file configFile,
// validates the contents, and populates a map of Config structs with the resulting
// values.
//
// The returned map contains one key per configuration file section.
func LoadConfig(configFile string) (map[string]*Config, error) {
	cfgList := make(map[string]*Config)

	f, err := loadInterpolatedConfigFile(configFile)
	if err != nil {
		return nil, err
	}

	validate := validator.New(validator.WithRequiredStructEnabled())

	for _, section := range f.Sections() {
		name := section.Name()
		if name == ini.DefaultSection {
			continue
		}

		// Handle any keys that have been deprecated
		handleDeprecatedKeys(section)
		// Apply any needed data transformation on the config prior to validation
		normaliseConfig(section)

		c := newDefaultConfig()
		if err := section.StrictMapTo(&c); err != nil {
			return nil, err
		}

		// Validate against struct tags using validator
		if err := validate.Struct(&c); err != nil {
			return nil, fmt.Errorf("error in section '%s': %w", name, err)
		}

		// Additional validations
		if err := checkAuthConfig(c.Username, c.Password, c.ApiKey); err != nil {
			return nil, err
		}

		cfgList[name] = &c
	}

	return cfgList, nil
}

// CertName builds a certificate name using the supplied base name and the current date/time.
//
// Returns a string with the constructed certificate name.
func (c *Config) CertName() string {
	if c.certName == "" {
		c.certName = c.CertBasename + strftime.Format("-%Y-%m-%d-%s", time.Now())
	}
	return c.certName
}

// ServerURL builds a URL for the server API endpoint by combining the protocol, hostname, and port.
//
// Returns a string with the constructed URL.
func (c *Config) ServerURL() string {
	if c.serverURL == "" {
		c.serverURL = fmt.Sprintf("%s://%s:%d", c.Protocol, c.ConnectHost, c.Port)
	}
	return c.serverURL
}

// normaliseConfig applies data transformations to user-supplied configuration to standardise the format.
func normaliseConfig(section *ini.Section) {
	// Lower-case some config items to make them effectively case-insensitive
	targetKeys := []string{"protocol", "client_api"}
	for _, keyName := range targetKeys {
		if section.HasKey(keyName) {
			curVal := section.Key(keyName).String()
			section.Key(keyName).SetValue(strings.ToLower(curVal))
		}
	}
}

// LoadInterpolatedConfigFile reads configuration information from the named configuration file and
// interpolates environment variables to their defined values.
func loadInterpolatedConfigFile(filename string) (*ini.File, error) {
	fileData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Convert the file content to a string and expand out any environment variables
	expandedConfig := os.ExpandEnv(string(fileData))
	f, err := ini.Load([]byte(expandedConfig))
	if err != nil {
		return nil, err
	}

	return f, nil
}

// CheckAuthConfig checks that authentication information has been provided and warns
// if both API key and username/password have been defined.
//
// An error is returned if no authentication information has been specified.
func checkAuthConfig(username string, password string, apiKey string) error {
	hasApiKey := apiKey != ""
	hasUserCreds := username != "" && password != ""

	// We should have *either* API Key *or* username/password
	if !hasApiKey && !hasUserCreds {
		return fmt.Errorf("no authentication is defined: you must provide either api_key OR username and password")
	}

	// Warning if all three are provided
	if hasApiKey && hasUserCreds {
		// There's probably a better way to surface this warning...
		fmt.Printf("WARNING: Both api_key and username/password are defined. The username and password will be ignored.\n")
	}
	return nil
}

// HandleDeprecatedKeys provides logic to handle any config file keys that have been deprecated.
// If the key has a replacement (i.e. it is renamed) then we map that here.
// Warnings are displayed for any deprecated keys in the user's configuration file.
func handleDeprecatedKeys(section *ini.Section) {
	if section.HasKey("timeoutSeconds") {
		fmt.Printf("WARNING: Section '%s' uses the deprecated key timeoutSeconds. Please update your config to use timeout_seconds instead.\n", section.Name())
		if !section.HasKey("timeout_seconds") {
			oldValue := section.Key("timeoutSeconds").Value()
			section.Key("timeout_seconds").SetValue(oldValue)
		}
	}
}

// newDefaultConfig returns an instance of Config prepopulated with default values.
func newDefaultConfig() Config {
	return Config{
		AddAsAppCertificate: false,
		AddAsFTPCertificate: false,
		AddAsUiCertificate:  false,
		CertBasename:        Default_base_cert_name,
		ClientApi:           "wsapi",
		Debug:               false,
		DeleteOldCerts:      false,
		Port:                Default_port,
		Protocol:            Default_protocol,
		StrictBasenameMatch: false,
		TlsSkipVerify:       false,
		TimeoutSeconds:      Default_timeout_seconds,
	}
}
