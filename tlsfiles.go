package configra

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"time"
)

func loadTLSFiles(options ClientOptions) (*tls.Config, error) {
	if options.ClientKeyFile != "" && options.ClientCertificateFile == "" {
		return nil, invalidInitialization("cert_file", "is missing while a private key file is configured", "Supply the issued client certificate, not the CA certificate.")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if options.ClientCertificateFile != "" {
		certificatePEM, err := readCredential(options.ClientCertificateFile, 128<<10)
		if err != nil {
			return nil, credentialReadError("cert_file", err)
		}
		defer clear(certificatePEM) // A combined PEM can also contain the private key.
		keyPEM := certificatePEM
		if options.ClientKeyFile != "" {
			keyPEM, err = readCredential(options.ClientKeyFile, 64<<10)
			if err != nil {
				return nil, credentialReadError("key_file", err)
			}
			defer clear(keyPEM)
		}
		certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
		if err != nil {
			return nil, invalidInitialization("cert_file", "does not contain a usable certificate/private-key pair", "Provide matching PEM files for certificate and key, or one combined PEM containing both. A public certificate alone and encrypted/P12 keys are not supported by this file loader.")
		}
		leaf := certificate.Leaf
		if leaf == nil {
			leaf, err = x509.ParseCertificate(certificate.Certificate[0])
			if err != nil {
				return nil, invalidInitialization("cert_file", "has an invalid leaf certificate", "Use a newly issued client certificate in PEM format.")
			}
		}
		if leaf.IsCA {
			return nil, invalidInitialization("cert_file", "contains a CA instead of a client identity", "Issue a client certificate in Administration; never distribute the CA signing key to an application.")
		}
		now := time.Now()
		if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
			return nil, invalidInitialization("cert_file", "is expired or is not yet valid", "Check the system clock and deploy a currently valid client certificate.")
		}
		allowsClient := len(leaf.ExtKeyUsage) == 0 && len(leaf.UnknownExtKeyUsage) == 0
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
				allowsClient = true
			}
		}
		if !allowsClient {
			return nil, invalidInitialization("cert_file", "does not permit client authentication", "Use a client-auth certificate, not the HTTPS server certificate.")
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	if options.ServerCAFile != "" {
		serverCA, err := readCredential(options.ServerCAFile, 1<<20)
		if err != nil {
			return nil, credentialReadError("server_ca_file", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(serverCA) {
			return nil, invalidInitialization("server_ca_file", "contains no valid PEM certificates", "Use the CA that issued the API HTTPS certificate, not the managed client CA. Omit this option for public Web PKI.")
		}
		config.RootCAs = roots
	}
	return config, nil
}

func readCredential(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("credential path is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, errors.New("invalid credential file")
	}
	return data, nil
}
