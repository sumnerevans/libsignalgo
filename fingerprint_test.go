package libsignalgo_test

// These tests copied from PublicAPITests.swift

import (
	"testing"

	"github.com/beeper/libsignalgo"
	"github.com/stretchr/testify/assert"
)

var (
	ALICE_IDENTITY = []byte{0x05, 0x06, 0x86, 0x3b, 0xc6, 0x6d, 0x02, 0xb4, 0x0d, 0x27, 0xb8, 0xd4, 0x9c, 0xa7, 0xc0, 0x9e, 0x92, 0x39, 0x23, 0x6f, 0x9d, 0x7d, 0x25, 0xd6, 0xfc, 0xca, 0x5c, 0xe1, 0x3c, 0x70, 0x64, 0xd8, 0x68}
	BOB_IDENTITY   = []byte{0x05, 0xf7, 0x81, 0xb6, 0xfb, 0x32, 0xfe, 0xd9, 0xba, 0x1c, 0xf2, 0xde, 0x97, 0x8d, 0x4d, 0x5d, 0xa2, 0x8d, 0xc3, 0x40, 0x46, 0xae, 0x81, 0x44, 0x02, 0xb5, 0xc0, 0xdb, 0xd9, 0x6f, 0xda, 0x90, 0x7b}

	VERSION_1                      = 1
	DISPLAYABLE_FINGERPRINT_V1     = "300354477692869396892869876765458257569162576843440918079131"
	ALICE_SCANNABLE_FINGERPRINT_V1 = []byte{0x08, 0x01, 0x12, 0x22, 0x0a, 0x20, 0x1e, 0x30, 0x1a, 0x03, 0x53, 0xdc, 0xe3, 0xdb, 0xe7, 0x68, 0x4c, 0xb8, 0x33, 0x6e, 0x85, 0x13, 0x6c, 0xdc, 0x0e, 0xe9, 0x62, 0x19, 0x49, 0x4a, 0xda, 0x30, 0x5d, 0x62, 0xa7, 0xbd, 0x61, 0xdf, 0x1a, 0x22, 0x0a, 0x20, 0xd6, 0x2c, 0xbf, 0x73, 0xa1, 0x15, 0x92, 0x01, 0x5b, 0x6b, 0x9f, 0x16, 0x82, 0xac, 0x30, 0x6f, 0xea, 0x3a, 0xaf, 0x38, 0x85, 0xb8, 0x4d, 0x12, 0xbc, 0xa6, 0x31, 0xe9, 0xd4, 0xfb, 0x3a, 0x4d}
	BOB_SCANNABLE_FINGERPRINT_V1   = []byte{0x08, 0x01, 0x12, 0x22, 0x0a, 0x20, 0xd6, 0x2c, 0xbf, 0x73, 0xa1, 0x15, 0x92, 0x01, 0x5b, 0x6b, 0x9f, 0x16, 0x82, 0xac, 0x30, 0x6f, 0xea, 0x3a, 0xaf, 0x38, 0x85, 0xb8, 0x4d, 0x12, 0xbc, 0xa6, 0x31, 0xe9, 0xd4, 0xfb, 0x3a, 0x4d, 0x1a, 0x22, 0x0a, 0x20, 0x1e, 0x30, 0x1a, 0x03, 0x53, 0xdc, 0xe3, 0xdb, 0xe7, 0x68, 0x4c, 0xb8, 0x33, 0x6e, 0x85, 0x13, 0x6c, 0xdc, 0x0e, 0xe9, 0x62, 0x19, 0x49, 0x4a, 0xda, 0x30, 0x5d, 0x62, 0xa7, 0xbd, 0x61, 0xdf}

	VERSION_2                      = 2
	DISPLAYABLE_FINGERPRINT_V2     = DISPLAYABLE_FINGERPRINT_V1
	ALICE_SCANNABLE_FINGERPRINT_V2 = []byte{0x08, 0x02, 0x12, 0x22, 0x0a, 0x20, 0x1e, 0x30, 0x1a, 0x03, 0x53, 0xdc, 0xe3, 0xdb, 0xe7, 0x68, 0x4c, 0xb8, 0x33, 0x6e, 0x85, 0x13, 0x6c, 0xdc, 0x0e, 0xe9, 0x62, 0x19, 0x49, 0x4a, 0xda, 0x30, 0x5d, 0x62, 0xa7, 0xbd, 0x61, 0xdf, 0x1a, 0x22, 0x0a, 0x20, 0xd6, 0x2c, 0xbf, 0x73, 0xa1, 0x15, 0x92, 0x01, 0x5b, 0x6b, 0x9f, 0x16, 0x82, 0xac, 0x30, 0x6f, 0xea, 0x3a, 0xaf, 0x38, 0x85, 0xb8, 0x4d, 0x12, 0xbc, 0xa6, 0x31, 0xe9, 0xd4, 0xfb, 0x3a, 0x4d}
	BOB_SCANNABLE_FINGERPRINT_V2   = []byte{0x08, 0x02, 0x12, 0x22, 0x0a, 0x20, 0xd6, 0x2c, 0xbf, 0x73, 0xa1, 0x15, 0x92, 0x01, 0x5b, 0x6b, 0x9f, 0x16, 0x82, 0xac, 0x30, 0x6f, 0xea, 0x3a, 0xaf, 0x38, 0x85, 0xb8, 0x4d, 0x12, 0xbc, 0xa6, 0x31, 0xe9, 0xd4, 0xfb, 0x3a, 0x4d, 0x1a, 0x22, 0x0a, 0x20, 0x1e, 0x30, 0x1a, 0x03, 0x53, 0xdc, 0xe3, 0xdb, 0xe7, 0x68, 0x4c, 0xb8, 0x33, 0x6e, 0x85, 0x13, 0x6c, 0xdc, 0x0e, 0xe9, 0x62, 0x19, 0x49, 0x4a, 0xda, 0x30, 0x5d, 0x62, 0xa7, 0xbd, 0x61, 0xdf}
)

// From PublicAPITests.swift:testFingerprint
func TestFingerprint(t *testing.T) {
	aliceStableID := []byte("+14152222222")
	bobStableID := []byte("+14153333333")

	aliceIdentityKey, err := libsignalgo.DeserializePublicKey(ALICE_IDENTITY)
	assert.NoError(t, err)
	bobIdentityKey, err := libsignalgo.DeserializePublicKey(BOB_IDENTITY)
	assert.NoError(t, err)

	t.Run("V1", func(t *testing.T) {
		aliceFingerprint, err := libsignalgo.NewFingerprint(
			5200, libsignalgo.FingerprintVersionV1,
			aliceStableID, aliceIdentityKey,
			bobStableID, bobIdentityKey)
		assert.NoError(t, err)

		bobFingerprint, err := libsignalgo.NewFingerprint(
			5200, libsignalgo.FingerprintVersionV1,
			bobStableID, bobIdentityKey,
			aliceStableID, aliceIdentityKey)
		assert.NoError(t, err)

		displayableAlice, err := aliceFingerprint.DisplayString()
		assert.NoError(t, err)
		assert.Equal(t, DISPLAYABLE_FINGERPRINT_V1, displayableAlice)

		displayableBob, err := bobFingerprint.DisplayString()
		assert.NoError(t, err)
		assert.Equal(t, DISPLAYABLE_FINGERPRINT_V1, displayableBob)

		scannableAlice, err := aliceFingerprint.ScannableEncoding()
		assert.NoError(t, err)
		assert.Equal(t, ALICE_SCANNABLE_FINGERPRINT_V1, scannableAlice)

		scannableBob, err := bobFingerprint.ScannableEncoding()
		assert.NoError(t, err)
		assert.Equal(t, BOB_SCANNABLE_FINGERPRINT_V1, scannableBob)
	})

	t.Run("V2", func(t *testing.T) {
		aliceFingerprint, err := libsignalgo.NewFingerprint(
			5200, libsignalgo.FingerprintVersionV2,
			aliceStableID, aliceIdentityKey,
			bobStableID, bobIdentityKey)
		assert.NoError(t, err)

		bobFingerprint, err := libsignalgo.NewFingerprint(
			5200, libsignalgo.FingerprintVersionV2,
			bobStableID, bobIdentityKey,
			aliceStableID, aliceIdentityKey)
		assert.NoError(t, err)

		displayableAlice, err := aliceFingerprint.DisplayString()
		assert.NoError(t, err)
		assert.Equal(t, DISPLAYABLE_FINGERPRINT_V2, displayableAlice)

		displayableBob, err := bobFingerprint.DisplayString()
		assert.NoError(t, err)
		assert.Equal(t, DISPLAYABLE_FINGERPRINT_V2, displayableBob)

		scannableAlice, err := aliceFingerprint.ScannableEncoding()
		assert.NoError(t, err)
		assert.Equal(t, ALICE_SCANNABLE_FINGERPRINT_V2, scannableAlice)

		scannableBob, err := bobFingerprint.ScannableEncoding()
		assert.NoError(t, err)
		assert.Equal(t, BOB_SCANNABLE_FINGERPRINT_V2, scannableBob)
	})

	t.Run("Mismatching fingerprints", func(t *testing.T) {
		mitmIdentityPrivateKey, err := libsignalgo.GeneratePrivateKey()
		assert.NoError(t, err)
		mitmIdentityKey, err := mitmIdentityPrivateKey.GetPublicKey()
		assert.NoError(t, err)

		aliceFingerprint, err := libsignalgo.NewFingerprint(
			5200, libsignalgo.FingerprintVersionV2,
			aliceStableID, aliceIdentityKey,
			bobStableID, mitmIdentityKey)
		assert.NoError(t, err)

		bobFingerprint, err := libsignalgo.NewFingerprint(
			5200, libsignalgo.FingerprintVersionV2,
			bobStableID, bobIdentityKey,
			aliceStableID, aliceIdentityKey)
		assert.NoError(t, err)

		displayableAlice, err := aliceFingerprint.DisplayString()
		assert.NoError(t, err)
		displayableBob, err := bobFingerprint.DisplayString()
		assert.NoError(t, err)
		assert.NotEqual(t, displayableAlice, displayableBob)

		scannableAlice, err := aliceFingerprint.ScannableEncoding()
		assert.NoError(t, err)
		scannableBob, err := bobFingerprint.ScannableEncoding()
		assert.NoError(t, err)
		assert.NotEqual(t, scannableAlice, scannableBob)
	})
}
