// Copyright 2018 The vault-operator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vaultutil

import (
	"bytes"
	"fmt"
	"path/filepath"

	api "github.com/coreos/vault-operator/pkg/apis/vault/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	vaultapi "github.com/hashicorp/vault/api"
	"k8s.io/client-go/kubernetes"
)

const (
	// VaultTLSAssetDir is the dir where vault's server TLS and etcd TLS assets sits
	VaultTLSAssetDir = "/run/vault/tls/"
	// ServerTLSCertName is the filename of the vault server cert
	ServerTLSCertName = "server.crt"
	// ServerTLSKeyName is the filename of the vault server key
	ServerTLSKeyName = "server.key"
)

var listenerFmt = `
listener "tcp" {
  address     = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file = "%s"
  tls_key_file  = "%s"
}
`

var etcdStorageFmt = `
storage "etcd" {
  address = "%s"
  etcd_api = "v3"
  ha_enabled = "true"
  tls_ca_file = "%s"
  tls_cert_file = "%s"
  tls_key_file = "%s"
  sync = "false"
}
`

// NewConfigWithDefaultParams appends to given config data some default params:
// - telemetry setting
// - tcp listener
func NewConfigWithDefaultParams(data string) string {
	buf := bytes.NewBufferString(data)
	buf.WriteString(`
telemetry {
	statsd_address = "localhost:9125"
}
`)

	listenerSection := fmt.Sprintf(listenerFmt,
		filepath.Join(VaultTLSAssetDir, ServerTLSCertName),
		filepath.Join(VaultTLSAssetDir, ServerTLSKeyName))
	buf.WriteString(listenerSection)

	return buf.String()
}

// NewConfigWithEtcd returns the new config data combining
// original config and new etcd storage section.
func NewConfigWithEtcd(data, etcdURL string) string {
	storageSection := fmt.Sprintf(etcdStorageFmt, etcdURL, filepath.Join(VaultTLSAssetDir, "etcd-client-ca.crt"),
		filepath.Join(VaultTLSAssetDir, "etcd-client.crt"), filepath.Join(VaultTLSAssetDir, "etcd-client.key"))
	data = fmt.Sprintf("%s%s", data, storageSection)
	return data
}

func NewClient(hostname string, port string, tlsConfig *vaultapi.TLSConfig) (*vaultapi.Client, error) {
	cfg := vaultapi.DefaultConfig()
	podURL := fmt.Sprintf("https://%s:%s", hostname, port)
	cfg.Address = podURL
	cfg.ConfigureTLS(tlsConfig)
	return vaultapi.NewClient(cfg)
}

// Auto Unseal Data
func AutoUnsealConfig(kubecli kubernetes.Interface, data string, v *api.VaultService) string {

	se, err := kubecli.CoreV1().Secrets(v.Namespace).Get(v.Spec.AutoUnsealProviderSecret, metav1.GetOptions{})
	if err != nil {
		str := fmt.Sprintf("Setup AWS KMS Config Failed: Get secret failed: %v", err)
		return str
	}

	buf := bytes.NewBufferString(data)

	if ( v.Spec.AutoUnsealProvider == "awskms" ){
		buf.WriteString(`
seal "awskms" {
  region     = "`+string(se.Data["region"])+`"
  access_key = "`+string(se.Data["access_key"])+`"
  secret_key = "`+string(se.Data["secret_key"])+`"
  kms_key_id = "`+string(se.Data["kms_key_id"])+`"
}
`)
	}else if ( v.Spec.AutoUnsealProvider == "azurekeyvault" ){
		buf.WriteString(`
seal "azurekeyvault" {
  tenant_id     = "`+string(se.Data["tenant_id"])+`"
  client_id = "`+string(se.Data["client_id"])+`"
  client_secret = "`+string(se.Data["client_secret"])+`"
  vault_name = "`+string(se.Data["vault_name"])+`"
  key_name = "`+string(se.Data["key_name"])+`"
}
`)
	}else if ( v.Spec.AutoUnsealProvider == "gcpckms" ){
		buf.WriteString(`
seal "gcpckms" {
  credentials     = "`+string(se.Data["credentials"])+`"
  project = "`+string(se.Data["project"])+`"
  region = "`+string(se.Data["region"])+`"
  key_ring = "`+string(se.Data["key_ring"])+`"
  crypto_key = "`+string(se.Data["crypto_key"])+`"
}
`)
	}else if ( v.Spec.AutoUnsealProvider == "alicloudkms" ){
		buf.WriteString(`
seal "alicloudkms" {
  region     = "`+string(se.Data["region"])+`"
  access_key = "`+string(se.Data["access_key"])+`"
  secret_key = "`+string(se.Data["secret_key"])+`"
  kms_key_id = "`+string(se.Data["kms_key_id"])+`"
}
`)
	}
	
	return buf.String()
}


func EnableWebUIConfig(kubecli kubernetes.Interface, data string, v *api.VaultService) string {

	fmt.Printf("Enabling WebUI\n")

	buf := bytes.NewBufferString(data)

	if ( v.Spec.EnableWebUI == true ){
		buf.WriteString(`
ui = true
`)}else{
	buf.WriteString(`
ui = false
`)
  }
	return buf.String()
}