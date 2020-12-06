// Copyright  The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kafkaexporter

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/Shopify/sarama"
	"github.com/xdg/scram"

	"go.opentelemetry.io/collector/config/configtls"
)

// XDGSCRAMClient defines XDGSCRAMClient
type XDGSCRAMClient struct {
	*scram.Client
	*scram.ClientConversation
	scram.HashGeneratorFcn
}

// Authentication defines authentication.
type Authentication struct {
	PlainText *PlainTextConfig            `mapstructure:"plain_text"`
	SCRAM     *SCRAMConfig                `mapstructure:"scram"`
	TLS       *configtls.TLSClientSetting `mapstructure:"tls"`
	Kerberos  *KerberosConfig             `mapstructure:"kerberos"`
}

// PlainTextConfig defines plaintext authentication.
type PlainTextConfig struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// SCRAMConfig defines plaintext authentication.
type SCRAMConfig struct {
	Username  string `mapstructure:"username"`
	Password  string `mapstructure:"password"`
	Algorithm string `mapstructure:"algorithm"`
}

// KerberosConfig defines kereros configuration.
type KerberosConfig struct {
	ServiceName string `mapstructure:"service_name"`
	Realm       string `mapstructure:"realm"`
	UseKeyTab   bool   `mapstructure:"use_keytab"`
	Username    string `mapstructure:"username"`
	Password    string `mapstructure:"password" json:"-"`
	ConfigPath  string `mapstructure:"config_file"`
	KeyTabPath  string `mapstructure:"keytab_file"`
}

// ConfigureAuthentication configures authentication in sarama.Config.
func ConfigureAuthentication(config Authentication, saramaConfig *sarama.Config) error {
	if config.PlainText != nil {
		configurePlaintext(*config.PlainText, saramaConfig)
	}
	if config.TLS != nil {
		if err := configureTLS(*config.TLS, saramaConfig); err != nil {
			return err
		}
	}
	if config.SCRAM != nil {
		if err := configureSCRAM(*config.SCRAM, saramaConfig); err != nil {
			return err
		}
	}

	if config.Kerberos != nil {
		configureKerberos(*config.Kerberos, saramaConfig)
	}
	return nil
}

func configurePlaintext(config PlainTextConfig, saramaConfig *sarama.Config) {
	saramaConfig.Net.SASL.Enable = true
	saramaConfig.Net.SASL.User = config.Username
	saramaConfig.Net.SASL.Password = config.Password
}

func configureSCRAM(config SCRAMConfig, saramaConfig *sarama.Config) error {
	saramaConfig.Net.SASL.Enable = true
	saramaConfig.Net.SASL.User = config.Username
	saramaConfig.Net.SASL.Password = config.Password
	if config.Algorithm != "sha256" && config.Algorithm != "sha512" {
		return fmt.Errorf("invalid SHA algorithm \"%s\": can be either \"sha256\" or \"sha512\"", config.Algorithm)
	}
	if config.Algorithm == "sha512" {

		saramaConfig.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient { return &XDGSCRAMClient{HashGeneratorFcn: sha512.New} }
		saramaConfig.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA512
	}

	if config.Algorithm == "sha256" {

		saramaConfig.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient { return &XDGSCRAMClient{HashGeneratorFcn: sha256.New} }
		saramaConfig.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256

	}

	return nil
}

func configureTLS(config configtls.TLSClientSetting, saramaConfig *sarama.Config) error {
	tlsConfig, err := config.LoadTLSConfig()
	if err != nil {
		return fmt.Errorf("error loading tls config: %w", err)
	}
	saramaConfig.Net.TLS.Enable = true
	saramaConfig.Net.TLS.Config = tlsConfig
	return nil
}

func configureKerberos(config KerberosConfig, saramaConfig *sarama.Config) {
	saramaConfig.Net.SASL.Mechanism = sarama.SASLTypeGSSAPI
	saramaConfig.Net.SASL.Enable = true
	if config.UseKeyTab {
		saramaConfig.Net.SASL.GSSAPI.KeyTabPath = config.KeyTabPath
		saramaConfig.Net.SASL.GSSAPI.AuthType = sarama.KRB5_KEYTAB_AUTH
	} else {
		saramaConfig.Net.SASL.GSSAPI.AuthType = sarama.KRB5_USER_AUTH
		saramaConfig.Net.SASL.GSSAPI.Password = config.Password
	}
	saramaConfig.Net.SASL.GSSAPI.KerberosConfigPath = config.ConfigPath
	saramaConfig.Net.SASL.GSSAPI.Username = config.Username
	saramaConfig.Net.SASL.GSSAPI.Realm = config.Realm
	saramaConfig.Net.SASL.GSSAPI.ServiceName = config.ServiceName
}

func (x *XDGSCRAMClient) Begin(userName, password, authzID string) (err error) {
	x.Client, err = x.HashGeneratorFcn.NewClient(userName, password, authzID)
	if err != nil {
		return err
	}
	x.ClientConversation = x.Client.NewConversation()
	return nil
}

func (x *XDGSCRAMClient) Step(challenge string) (response string, err error) {
	response, err = x.ClientConversation.Step(challenge)
	return
}

func (x *XDGSCRAMClient) Done() bool {
	return x.ClientConversation.Done()
}
