//go:build cgo && !js && !wasip1 && !tinygo && !gofuzz && (linux || darwin) && (amd64 || arm64)

package builder

import (
	"strconv"
	"testing"

	"github.com/Peersyst/xrpl-go/confidential/elgamal"
	xrplhash "github.com/Peersyst/xrpl-go/xrpl/hash"
	"github.com/stretchr/testify/require"
)

// The decryption itself needs the native backend, so the cases that run one carry the CGo
// tag. Everything GetSpendingBalance decides before or without decrypting lives in
// balance_test.go, so a CGO_ENABLED=0 run still covers it.

// encryptUnder encrypts an amount under a public key with a fresh blinding factor, which is
// how the ledger's own confidential balances are formed.
func encryptUnder(t *testing.T, amount uint64, pubKeyHex string) string {
	t.Helper()

	blindingFactor, err := elgamal.GenerateBlindingFactor()
	require.NoError(t, err)
	ciphertext, err := elgamal.Encrypt(amount, pubKeyHex, blindingFactor)
	require.NoError(t, err)
	return ciphertext
}

// TestGetSpendingBalanceDecryptsSpendingBalance pins the whole point of the reader: the
// ledger holds a ciphertext, and the holder's own private key turns it back into an amount.
// The MPToken also carries an inbox encrypting a different amount, which the result must
// not include: XLS-96 leaves an inbox unspendable until a ConfidentialMPTMergeInbox moves
// it into the spending balance.
func TestGetSpendingBalanceDecryptsSpendingBalance(t *testing.T) {
	const spendingBalance, inboxBalance uint64 = 250, 77

	holderKP, q := newBalanceLedgerFixture(t, 0, 3, spendingBalance)
	mptokenIndex, err := xrplhash.MPToken(testIssuanceID, testAccount)
	require.NoError(t, err)
	q.entries[mptokenIndex]["ConfidentialBalanceInbox"] = encryptUnder(t, inboxBalance, holderKP.PubKeyHex)

	params := spendingBalanceParams()
	params.HolderPrivKey = holderKP.PrivKeyHex
	params.BalanceRange = elgamal.AmountRange{Low: 0, High: spendingBalance}

	balance, err := GetSpendingBalance(q, params)
	require.NoError(t, err)
	require.Equal(t, spendingBalance, balance)
	require.Empty(t, q.accountRequests, "reading a balance needs no account sequence")
}

// TestGetSpendingBalanceDecryptsEncryptedZero pins that a holder who converted and then
// spent everything reads as zero through the ciphertext, the same answer a holder with no
// ciphertext at all gets without decrypting.
func TestGetSpendingBalanceDecryptsEncryptedZero(t *testing.T) {
	holderKP, q := newBalanceLedgerFixture(t, 0, 1, 0)

	params := spendingBalanceParams()
	params.HolderPrivKey = holderKP.PrivKeyHex
	params.BalanceRange = elgamal.AmountRange{Low: 0, High: 0}

	balance, err := GetSpendingBalance(q, params)
	require.NoError(t, err)
	require.Zero(t, balance)
}

// TestGetSpendingBalanceSearchesPastTheGivenHighUpToTheSupply pins that a range wider than
// the issuance's confidential supply still decrypts, because capping it at the supply can
// never exclude a balance.
func TestGetSpendingBalanceSearchesWiderRangesUpToTheSupply(t *testing.T) {
	const spendingBalance, outstanding uint64 = 250, 1000

	holderKP, q := newBalanceLedgerFixture(t, 0, 1, spendingBalance)
	issuanceIndex, err := xrplhash.MPTokenIssuance(testIssuanceID)
	require.NoError(t, err)
	q.entries[issuanceIndex]["ConfidentialOutstandingAmount"] = strconv.FormatUint(outstanding, 10)

	params := spendingBalanceParams()
	params.HolderPrivKey = holderKP.PrivKeyHex
	params.BalanceRange = elgamal.AmountRange{Low: 0, High: outstanding * 1000}

	balance, err := GetSpendingBalance(q, params)
	require.NoError(t, err)
	require.Equal(t, spendingBalance, balance)
}

// TestGetSpendingBalanceReportsFailedBoundedSearch pins what a bounded search costs when
// the bounds are wrong: the balance is not found, and the failure says so rather than
// widening the search on its own. The private key must not appear in the message.
func TestGetSpendingBalanceReportsFailedBoundedSearch(t *testing.T) {
	const spendingBalance uint64 = 250

	tests := []struct {
		name         string
		balanceRange elgamal.AmountRange
	}{
		{name: "range ends below the balance", balanceRange: elgamal.AmountRange{Low: 0, High: spendingBalance - 1}},
		{name: "range starts above the balance", balanceRange: elgamal.AmountRange{Low: spendingBalance + 1, High: spendingBalance + 10}},
		{name: "default range searches zero alone", balanceRange: elgamal.AmountRange{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			holderKP, q := newBalanceLedgerFixture(t, 0, 1, spendingBalance)

			params := spendingBalanceParams()
			params.HolderPrivKey = holderKP.PrivKeyHex
			params.BalanceRange = test.balanceRange

			_, err := GetSpendingBalance(q, params)
			require.ErrorIs(t, err, ErrCryptoFailed)
			require.ErrorIs(t, err, elgamal.ErrDecryptFailed)
			require.NotContains(t, err.Error(), holderKP.PrivKeyHex)
		})
	}
}

// TestGetSpendingBalanceRejectsAnotherHoldersKey pins that a key that decrypts nothing on
// this ciphertext fails the search rather than returning some other holder's amount.
func TestGetSpendingBalanceRejectsAnotherHoldersKey(t *testing.T) {
	const spendingBalance uint64 = 250

	_, q := newBalanceLedgerFixture(t, 0, 1, spendingBalance)
	otherKP, err := elgamal.GenerateKeypair()
	require.NoError(t, err)

	params := spendingBalanceParams()
	params.HolderPrivKey = otherKP.PrivKeyHex
	params.BalanceRange = elgamal.AmountRange{Low: 0, High: spendingBalance}

	_, err = GetSpendingBalance(q, params)
	require.ErrorIs(t, err, ErrCryptoFailed)
	require.ErrorIs(t, err, elgamal.ErrDecryptFailed)
	require.NotContains(t, err.Error(), otherKP.PrivKeyHex)
}
