// Package crl implements the HTTP handler for the crl commands.
package crl

import (
	"crypto/x509/pkix"
	"encoding/json"
	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// This type is meant to be unmarshalled from JSON
type jsonCRLRequest struct {
	ExpiryTime   string   `json:"expireTime"`
}

// Handle responds to requests for crl generation. It creates this crl
// based off of the given certificate, serial numbers, and private key
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) error {

	var revokedCerts []pkix.RevokedCertificate
	var oneWeek = time.Duration(604800) * time.Second
	var newExpiryTime = time.Now()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	req := &jsonCRLRequest{}

	err = json.Unmarshal(body, req)
	if err != nil {
		log.Error(err)
	}

	if req.ExpiryTime != "" {
		expiryTime := strings.TrimSpace(req.ExpiryTime)
		expiryInt, err := strconv.ParseInt(expiryTime, 0, 32)
		if err != nil {
			return err
		}

		newExpiryTime = time.Now().Add((time.Duration(expiryInt) * time.Second))
	}

	if req.ExpiryTime == "" {
		newExpiryTime = time.Now().Add(oneWeek)
	}

	if err != nil {
		return err
	}
    
    expiredCerts, err := h.dbAccessor.GetExpiredCertificates()
    
    if err != nil {
		log.Error(err)
        return err
	}
    
    for _, c := range expiredCerts {
        tempBigInt := new(big.Int)
        tempBigInt.SetString(c.Serial, 10)
        tempCert := pkix.RevokedCertificate{
            SerialNumber:   tempBigInt,
            RevocationTime: time.Now(),
        }
        revokedCerts = append(revokedCerts, tempCert)
    }
    
	result, err := h.signer.CreateCRL(revokedCerts, time.Now(), newExpiryTime)

	return api.SendResponse(w, result)
}

// A Handler accepts requests with a serial number parameter
// and revokes
type Handler struct {
	dbAccessor certdb.Accessor
    signer signer.Signer
}

// NewHandler returns a new http.Handler that handles a revoke request.
func NewHandler(dbAccessor certdb.Accessor, signer signer.Signer) http.Handler {
	return &api.HTTPHandler{
		Handler: &Handler{
			dbAccessor: dbAccessor,
			signer:    signer,
		},
		Methods: []string{"POST"},
	}
}

