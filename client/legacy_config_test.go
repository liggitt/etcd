package client

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCustomDialerFor(t *testing.T) {
	{
		dialer := customDialerFor(0)
		if dialer != nil {
			t.Errorf("Expected nil dialer for 0 timeout, got non-nil")
		}
	}

	{
		dialer := customDialerFor(time.Second)
		if dialer == nil {
			t.Errorf("Expected non-nil dialer for non-zero timeout, got nil")
		}
	}
}

func TestCustomTLSConfigFor(t *testing.T) {
	certFile := "localhost.tmp.crt"
	keyFile := "localhost.tmp.key"
	invalidFile := "invalid.tmp"

	ioutil.WriteFile(certFile, localhostCert, os.FileMode(0700))
	defer os.Remove(certFile)

	ioutil.WriteFile(keyFile, localhostKey, os.FileMode(0700))
	defer os.Remove(keyFile)

	ioutil.WriteFile(invalidFile, invalidData, os.FileMode(0700))
	defer os.Remove(invalidFile)

	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(localhostCert)

	testcases := map[string]struct {
		CertFile          string
		KeyFile           string
		CAFiles           []string
		ExpectedErr       string
		ExpectedTLSConfig *tls.Config
	}{
		"empty": {
			CertFile:          "",
			KeyFile:           "",
			CAFiles:           []string{},
			ExpectedErr:       "",
			ExpectedTLSConfig: nil,
		},

		"client cert": {
			CertFile:          certFile,
			KeyFile:           keyFile,
			ExpectedTLSConfig: &tls.Config{Certificates: []tls.Certificate{clientCert}},
		},
		"cert pool": {
			CAFiles:           []string{certFile},
			ExpectedTLSConfig: &tls.Config{RootCAs: caPool},
		},

		"missing certfile": {
			CertFile:    "invalid",
			KeyFile:     keyFile,
			ExpectedErr: "invalid: no such file",
		},
		"missing keyfile": {
			CertFile:    certFile,
			KeyFile:     "invalid",
			ExpectedErr: "invalid: no such file",
		},
		"missing ca file": {
			CAFiles:     []string{certFile, "invalid"},
			ExpectedErr: "invalid: no such file",
		},

		"invalid certfile": {
			CertFile:    invalidFile,
			KeyFile:     keyFile,
			ExpectedErr: "failed to parse certificate",
		},
		"invalid keyfile": {
			CertFile:    certFile,
			KeyFile:     invalidFile,
			ExpectedErr: "failed to parse key",
		},
	}

	for k, tc := range testcases {
		config, err := customTLSConfigFor(tc.CertFile, tc.KeyFile, tc.CAFiles)
		if err != nil {
			if len(tc.ExpectedErr) == 0 {
				t.Errorf("%s: Unexpected error: %v", k, err)
			} else if !strings.Contains(err.Error(), tc.ExpectedErr) {
				t.Errorf("%s: Expected error containing %q, got %v", k, tc.ExpectedErr, err)
			}
			continue
		}

		if !reflect.DeepEqual(tc.ExpectedTLSConfig, config) {
			t.Errorf("%s: Expected\n%#v\ngot\n%#v", k, tc.ExpectedTLSConfig, config)
		}
	}
}

func TestConfigFromLegacyConfig(t *testing.T) {
	certFile := "localhost.tmp.crt"
	keyFile := "localhost.tmp.key"

	ioutil.WriteFile(certFile, localhostCert, os.FileMode(0700))
	defer os.Remove(certFile)

	ioutil.WriteFile(keyFile, localhostKey, os.FileMode(0700))
	defer os.Remove(keyFile)

	config, err := ConfigFromLegacyConfigBytes([]byte(`{
  "cluster": {
    "machines":["a","b"]
  },
  "config": {
    "certFile": "localhost.tmp.crt",
    "keyFile": "localhost.tmp.key",
    "caCertFiles": ["localhost.tmp.crt"]
  }
}`))
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}
	if !reflect.DeepEqual(config.Endpoints, []string{"a", "b"}) {
		t.Fatalf("Unexpected endpoints %v", config.Endpoints)
	}
	if config.Transport == nil {
		t.Fatalf("Expected custom transport, got nil")
	}
}

// localhostCert is a PEM-encoded TLS cert with SAN IPs
// "127.0.0.1" and "[::1]", expiring at the last second of 2049 (the end
// of ASN.1 time).
// generated from src/crypto/tls:
// go run generate_cert.go  --rsa-bits 512 --host 127.0.0.1,::1,example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBdzCCASOgAwIBAgIBADALBgkqhkiG9w0BAQUwEjEQMA4GA1UEChMHQWNtZSBD
bzAeFw03MDAxMDEwMDAwMDBaFw00OTEyMzEyMzU5NTlaMBIxEDAOBgNVBAoTB0Fj
bWUgQ28wWjALBgkqhkiG9w0BAQEDSwAwSAJBAN55NcYKZeInyTuhcCwFMhDHCmwa
IUSdtXdcbItRB/yfXGBhiex00IaLXQnSU+QZPRZWYqeTEbFSgihqi1PUDy8CAwEA
AaNoMGYwDgYDVR0PAQH/BAQDAgCkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1Ud
EwEB/wQFMAMBAf8wLgYDVR0RBCcwJYILZXhhbXBsZS5jb22HBH8AAAGHEAAAAAAA
AAAAAAAAAAAAAAEwCwYJKoZIhvcNAQEFA0EAAoQn/ytgqpiLcZu9XKbCJsJcvkgk
Se6AbGXgSlq+ZCEVo0qIwSgeBqmsJxUu7NCSOwVJLYNEBO2DtIxoYVk+MA==
-----END CERTIFICATE-----`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBAN55NcYKZeInyTuhcCwFMhDHCmwaIUSdtXdcbItRB/yfXGBhiex0
0IaLXQnSU+QZPRZWYqeTEbFSgihqi1PUDy8CAwEAAQJBAQdUx66rfh8sYsgfdcvV
NoafYpnEcB5s4m/vSVe6SU7dCK6eYec9f9wpT353ljhDUHq3EbmE4foNzJngh35d
AekCIQDhRQG5Li0Wj8TM4obOnnXUXf1jRv0UkzE9AHWLG5q3AwIhAPzSjpYUDjVW
MCUXgckTpKCuGwbJk7424Nb8bLzf3kllAiA5mUBgjfr/WtFSJdWcPQ4Zt9KTMNKD
EUO0ukpTwEIl6wIhAMbGqZK3zAAFdq8DD2jPx+UJXnh0rnOkZBzDtJ6/iN69AiEA
1Aq8MJgTaYsDQWyU/hDq5YkDJc9e9DSCvUIzqxQWMQE=
-----END RSA PRIVATE KEY-----`)

var invalidData = []byte(`-----BEGIN CERTIFICATE-----
invalid data
-----END CERTIFICATE-----`)
