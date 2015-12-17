package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

type legacyClient struct {
	Config  legacyConfig   `json:"config"`
	Cluster *legacyCluster `json:"cluster"`
}

type legacyConfig struct {
	CertFile    string        `json:"certFile"`
	KeyFile     string        `json:"keyFile"`
	CaCertFile  []string      `json:"caCertFiles"`
	DialTimeout time.Duration `json:"timeout"`
	Consistency string        `json:"consistency"`
}

type legacyCluster struct {
	Leader   string   `json:"leader"`
	Machines []string `json:"machines"`
}

func ConfigFromLegacyConfigFile(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ConfigFromLegacyConfigBytes(data)
}

func ConfigFromLegacyConfigBytes(data []byte) (*Config, error) {
	c := &legacyClient{}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, err
	}

	config := &Config{}

	if c.Cluster != nil {
		config.Endpoints = c.Cluster.Machines
	}

	customTransport, err := customTransportFor(c.Config.CertFile, c.Config.KeyFile, c.Config.CaCertFile, c.Config.DialTimeout)
	if err != nil {
		return nil, err
	}
	config.Transport = customTransport

	return config, nil
}

func customTransportFor(certFile, keyFile string, caFiles []string, dialTimeout time.Duration) (*http.Transport, error) {
	customDialer := customDialerFor(dialTimeout)
	customTLSConfig, err := customTLSConfigFor(certFile, keyFile, caFiles)
	if err != nil {
		return nil, err
	}

	// If nothing custom is needed, return
	if customTLSConfig == nil && customDialer == nil {
		return nil, nil
	}

	// Start with the defaults from the DefaultTransport
	defaults := DefaultTransport.(*http.Transport)
	customTransport := &http.Transport{
		Proxy:               defaults.Proxy,
		Dial:                defaults.Dial,
		TLSHandshakeTimeout: defaults.TLSHandshakeTimeout,
	}

	// Override dialer if customized
	if customDialer != nil {
		customTransport.Dial = customDialer
	}
	// Override tls config if customized
	if customTLSConfig != nil {
		customTransport.TLSClientConfig = customTLSConfig
	}

	return customTransport, nil
}

func customTLSConfigFor(certFile, keyFile string, caFiles []string) (*tls.Config, error) {
	if certFile == "" && len(caFiles) == 0 {
		return nil, nil
	}

	tlsConfig := &tls.Config{}

	if certFile != "" {
		clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}

	if len(caFiles) > 0 {
		pool := x509.NewCertPool()
		for _, caFile := range caFiles {
			data, err := ioutil.ReadFile(caFile)
			if err != nil {
				return nil, err
			}
			pool.AppendCertsFromPEM(data)
		}
		tlsConfig.RootCAs = pool
	}

	return tlsConfig, nil
}

func customDialerFor(dialTimeout time.Duration) func(network, addr string) (net.Conn, error) {
	if dialTimeout == 0 {
		return nil
	}
	return (&net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}).Dial
}
