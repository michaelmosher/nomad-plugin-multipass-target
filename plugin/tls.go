package plugin

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func decodePemFile(path string) (*pem.Block, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("os.ReadFile: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("pem.Decode: no PEM data was found")
	}

	return block, nil
}

func parseClientCertificate(path string) (*x509.Certificate, error) {
	pemBlock, err := decodePemFile(path)
	if err != nil {
		return nil, fmt.Errorf("decodePemFile(%s): %w", path, err)
	}

	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParseCertificates: %w", err)
	}

	return cert, err
}

func parseClientKey(path string) (*ecdsa.PrivateKey, error) {
	pemBlock, err := decodePemFile(path)
	if err != nil {
		return nil, fmt.Errorf("decodePemFile(%s): %w", path, err)
	}

	parseResult, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKCS8PrivateKey: %w", err)
	}

	return parseResult.(*ecdsa.PrivateKey), nil
}
