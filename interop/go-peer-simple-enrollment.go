// Copyright (c) marcschier. Licensed under the MIT License.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"iter"
	"slices"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

func fixtureOwnerModules(modules []string, db *sqlite.DB) iter.Seq2[string, serviceinfo.OwnerModule] {
	return func(yield func(string, serviceinfo.OwnerModule) bool) {
		if slices.Contains(modules, "fdo.csr") {
			yield("fdo.csr", &fixtureEnrollment{db: db})
		}
	}
}

// Implements only this loopback probe's one P-256 PKCS#10 request.
type fixtureEnrollment struct {
	db          *sqlite.DB
	active      bool
	certificate []byte
}

func (m *fixtureEnrollment) HandleInfo(ctx context.Context, name string, body io.Reader) error {
	const maxBody = 4096
	encoded, err := io.ReadAll(io.LimitReader(body, maxBody+1))
	if err != nil {
		return err
	}
	if len(encoded) > maxBody {
		return errors.New("fixture enrollment item exceeds its size limit")
	}
	switch name {
	case "active":
		if m.active || len(encoded) != 1 || encoded[0] != 0xf5 {
			return errors.New("expected a single affirmative fixture activation")
		}
		m.active = true
		return nil
	case "simpleenroll-req":
		if !m.active || m.certificate != nil {
			return errors.New("fixture CSR is out of turn")
		}
	default:
		return errors.New("unsupported fixture enrollment message")
	}
	chain, _ := serviceinfo.DeviceCertificateFromContext(ctx)
	if len(chain) == 0 || chain[0].Subject.CommonName != "FDO peer fixture" {
		return errors.New("fixture CSR requires the authenticated test device")
	}
	var text string
	if err := cbor.Unmarshal(encoded, &text); err != nil {
		return err
	}
	der, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(der) != text {
		return errors.New("fixture CSR is not canonical Base64")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return err
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || csr.Subject.CommonName != "FDO peer enrollment" {
		return errors.New("CSR does not match the P-256 enrollment fixture")
	}
	if err := csr.CheckSignature(); err != nil {
		return err
	}
	signer, issuer, err := m.db.ManufacturerKey(ctx, protocol.Secp384r1KeyType, 0)
	if err != nil {
		return err
	}
	if len(issuer) != 1 {
		return errors.New("expected one ephemeral fixture CA")
	}
	now := time.Now()
	template := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "FDO peer enrollment"},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	m.certificate, err = x509.CreateCertificate(rand.Reader, template, issuer[0], key, signer)
	return err
}

func (m *fixtureEnrollment) ProduceInfo(_ context.Context, producer *serviceinfo.Producer) (bool, bool, error) {
	if m.certificate == nil {
		return false, false, errors.New("fixture enrollment request was not received")
	}
	const response = "simpleenroll-res"
	value, err := cbor.Marshal(base64.StdEncoding.EncodeToString(m.certificate))
	if err != nil {
		return false, false, err
	}
	if len(value) > producer.Available(response) {
		return false, false, errors.New("fixture enrollment certificate does not fit in one response")
	}
	if err := producer.WriteChunk(response, value); err != nil {
		return false, false, err
	}
	return false, true, nil
}
