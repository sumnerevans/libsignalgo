package libsignalgo_test

import (
	_ "embed"
	"encoding/base64"
	"testing"
	"time"

	"github.com/beeper/libsignalgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed resources/clienthandshakestart.data
var attestationMessage []byte
var currentDate = time.Unix(1655857680, 0)

func TestCreateCDS2Client(t *testing.T) {
	setupLogging()
	mrEnclave, err := base64.StdEncoding.DecodeString("OdePF/iqmo6c2vFllZR6BXusIfAU0av9apmy39ThjR0=")
	require.NoError(t, err)

	cds2Client, err := libsignalgo.NewCDS2Client(mrEnclave, attestationMessage, currentDate)
	assert.NoError(t, err)
	assert.NotNil(t, cds2Client)

	res, err := cds2Client.InitialRequest()
	assert.NoError(t, err)
	assert.Len(t, res, 48)
}

func TestCreateCDS2WithInvalidEnclave(t *testing.T) {
	setupLogging()
	mrEnclave := []byte{}
	_, err := libsignalgo.NewCDS2Client(mrEnclave, attestationMessage, currentDate)
	assert.Error(t, err)
}

func TestCreateCDS2WithInvalidAttestationMessage(t *testing.T) {
	setupLogging()
	mrEnclave, err := base64.StdEncoding.DecodeString("OdePF/iqmo6c2vFllZR6BXusIfAU0av9apmy39ThjR0=")
	require.NoError(t, err)

	_, err = libsignalgo.NewCDS2Client(mrEnclave, []byte{}, currentDate)
	assert.Error(t, err)

	_, err = libsignalgo.NewCDS2Client(mrEnclave, []byte{1}, currentDate)
	assert.Error(t, err)
}

func TestCDS2EstablishedReceiveFailsPriorToEstablishment(t *testing.T) {
	setupLogging()
	mrEnclave, err := base64.StdEncoding.DecodeString("OdePF/iqmo6c2vFllZR6BXusIfAU0av9apmy39ThjR0=")
	require.NoError(t, err)

	cds2Client, err := libsignalgo.NewCDS2Client(mrEnclave, attestationMessage, currentDate)
	require.NoError(t, err)

	_, err = cds2Client.EstablishedReceive([]byte{})
	assert.Error(t, err)
}
