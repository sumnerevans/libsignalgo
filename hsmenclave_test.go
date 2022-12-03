package libsignalgo_test

import (
	"testing"

	"github.com/beeper/libsignalgo"
	"github.com/stretchr/testify/assert"
)

var nullHash = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func getKeyBytes(t *testing.T) []byte {
	validKey, err := libsignalgo.GenerateIdentityKeyPair()
	assert.NoError(t, err)
	keyBytes, err := validKey.GetPublicKey().Bytes()
	assert.NoError(t, err)
	return keyBytes
}

func TestCreateHSMClient(t *testing.T) {
	setupLogging()
	// See HsmEnclaveTests.testCreateClient in the Swift tests.
	hashes := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		//
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	}
	t.Run("Succeeds with hashes", func(t *testing.T) {
		client, err := libsignalgo.NewHSMEnclaveClient(getKeyBytes(t), hashes)
		assert.NoError(t, err)

		initialMessage, err := client.InitialRequest()
		assert.NoError(t, err)
		assert.Len(t, initialMessage, 112)
	})

	t.Run("Fails with no hashes", func(t *testing.T) {
		_, err := libsignalgo.NewHSMEnclaveClient(getKeyBytes(t), []byte{})
		assert.Error(t, err)
	})
}

func TestHSMCompleteHandshakeWithoutInitialRequest(t *testing.T) {
	setupLogging()
	client, err := libsignalgo.NewHSMEnclaveClient(getKeyBytes(t), nullHash)
	assert.NoError(t, err)
	err = client.CompleteHandshake([]byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
}

func TestHSMEstablishedSendFailsPriorToEstablishment(t *testing.T) {
	setupLogging()
	client, err := libsignalgo.NewHSMEnclaveClient(getKeyBytes(t), nullHash)
	assert.NoError(t, err)
	_, err = client.EstablishedSend([]byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
}

func TestHSMEstablishedReceiveFailsPriorToEstablishment(t *testing.T) {
	setupLogging()
	client, err := libsignalgo.NewHSMEnclaveClient(getKeyBytes(t), nullHash)
	assert.NoError(t, err)
	_, err = client.EstablishedReceive([]byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
}
