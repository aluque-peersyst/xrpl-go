package builder

import (
	"errors"
	"strconv"
	"testing"

	"github.com/Peersyst/xrpl-go/confidential/elgamal"
	xrplhash "github.com/Peersyst/xrpl-go/xrpl/hash"
	ledgerentries "github.com/Peersyst/xrpl-go/xrpl/ledger-entry-types"
	"github.com/Peersyst/xrpl-go/xrpl/queries/common"
	"github.com/Peersyst/xrpl-go/xrpl/queries/ledger"
	"github.com/stretchr/testify/require"
)

// testHolderPrivKey is a valid secp256k1 scalar written out rather than generated, so the
// tests in this file run under CGO_ENABLED=0 too. Only the decryption itself needs the
// native backend, and every case here fails before it or never reaches it.
const testHolderPrivKey = "1111111111111111111111111111111111111111111111111111111111111111"

// balanceQuerier returns a querier holding testAccount's MPToken for testIssuanceID and
// that issuance, each omitted when nil, so a test can present a ledger missing either one.
func balanceQuerier(t *testing.T, mptoken, issuance ledgerentries.FlatLedgerObject) *mockQuerier {
	t.Helper()

	issuanceIndex, err := xrplhash.MPTokenIssuance(testIssuanceID)
	require.NoError(t, err)
	mptokenIndex, err := xrplhash.MPToken(testIssuanceID, testAccount)
	require.NoError(t, err)

	entries := map[string]ledgerentries.FlatLedgerObject{}
	if mptoken != nil {
		entries[mptokenIndex] = mptoken
	}
	if issuance != nil {
		entries[issuanceIndex] = issuance
	}
	return &mockQuerier{entries: entries}
}

// spendingBalanceParams returns params that resolve testAccount's balance, which each test
// narrows to the one input it exercises.
func spendingBalanceParams() SpendingBalanceParams {
	return SpendingBalanceParams{
		Holder:        testAccount,
		IssuanceID:    testIssuanceID,
		HolderPrivKey: testHolderPrivKey,
		BalanceRange:  elgamal.AmountRange{Low: 0, High: 1000},
	}
}

// unspendableCiphertext stands in for a spending balance the reader carries as far as the
// decryption and no further, so a test can reach that point without the native backend.
const unspendableCiphertext = "not-a-ciphertext"

// spendingMPToken returns an MPToken carrying a spending ciphertext, the state a holder
// reaches after its first inbox merge.
func spendingMPToken(balanceCt string) ledgerentries.FlatLedgerObject {
	return buildMPTokenEntry(mptokenFields{holderKey: testHolderKey, balanceCt: balanceCt, inboxCt: testInboxCt})
}

func TestGetSpendingBalanceRejectsInvalidParams(t *testing.T) {
	tests := []struct {
		name    string
		params  func(SpendingBalanceParams) SpendingBalanceParams
		wantErr error
	}{
		{
			name:    "missing holder",
			params:  func(p SpendingBalanceParams) SpendingBalanceParams { p.Holder = ""; return p },
			wantErr: ErrMissingHolder,
		},
		{
			name:    "malformed holder",
			params:  func(p SpendingBalanceParams) SpendingBalanceParams { p.Holder = "not-an-address"; return p },
			wantErr: ErrInvalidHolder,
		},
		{
			name:    "zero holder",
			params:  func(p SpendingBalanceParams) SpendingBalanceParams { p.Holder = zeroClassicAccount; return p },
			wantErr: ErrInvalidHolder,
		},
		{
			name:    "missing issuance ID",
			params:  func(p SpendingBalanceParams) SpendingBalanceParams { p.IssuanceID = ""; return p },
			wantErr: ErrMissingIssuanceID,
		},
		{
			name:    "malformed issuance ID",
			params:  func(p SpendingBalanceParams) SpendingBalanceParams { p.IssuanceID = "not-an-issuance"; return p },
			wantErr: ErrInvalidIssuanceID,
		},
		{
			// The issuer can never hold its own issuance confidentially, so it has no
			// MPToken to read and the ledger is never asked for one.
			name:    "holder is the issuer",
			params:  func(p SpendingBalanceParams) SpendingBalanceParams { p.IssuanceID = testIssuerIssuanceID; return p },
			wantErr: ErrIssuerNotAllowed,
		},
		{
			name:    "missing private key",
			params:  func(p SpendingBalanceParams) SpendingBalanceParams { p.HolderPrivKey = ""; return p },
			wantErr: ErrMissingHolderKey,
		},
		{
			name:    "malformed private key",
			params:  func(p SpendingBalanceParams) SpendingBalanceParams { p.HolderPrivKey = "abcd"; return p },
			wantErr: ErrInvalidPrivKey,
		},
		{
			name: "inverted range",
			params: func(p SpendingBalanceParams) SpendingBalanceParams {
				p.BalanceRange = elgamal.AmountRange{Low: 10, High: 1}
				return p
			},
			wantErr: elgamal.ErrInvalidAmountRange,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			q := balanceQuerier(t, spendingMPToken(unspendableCiphertext), buildIssuanceEntry(testHolderKey, ""))

			_, err := GetSpendingBalance(q, test.params(spendingBalanceParams()))
			require.ErrorIs(t, err, test.wantErr)
			require.Zero(t, q.queryCalls, "params must be rejected before any ledger query")
		})
	}
}

// TestGetSpendingBalanceReturnsZeroWithoutSpendingCiphertext pins the two states that read
// as a zero spending balance rather than as an error, and that neither costs an issuance
// read: a holder that never converted, and one whose only value sits in an inbox no merge
// has moved yet. The inbox is not spendable, so it is not this balance.
func TestGetSpendingBalanceReturnsZeroWithoutSpendingCiphertext(t *testing.T) {
	tests := []struct {
		name    string
		mptoken ledgerentries.FlatLedgerObject
	}{
		{name: "no confidential state", mptoken: buildMPTokenEntry(mptokenFields{})},
		{name: "registered but never converted", mptoken: buildMPTokenEntry(mptokenFields{holderKey: testHolderKey})},
		{name: "unmerged inbox only", mptoken: buildMPTokenEntry(mptokenFields{holderKey: testHolderKey, inboxCt: testInboxCt})},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			q := balanceQuerier(t, test.mptoken, buildIssuanceEntry(testHolderKey, ""))

			balance, err := GetSpendingBalance(q, spendingBalanceParams())
			require.NoError(t, err)
			require.Zero(t, balance)
			require.Len(t, q.entryRequests, 1, "an absent ciphertext answers from the MPToken alone")
			require.Empty(t, q.accountRequests, "reading a balance needs no account sequence")
		})
	}
}

func TestGetSpendingBalanceReportsMissingMPToken(t *testing.T) {
	q := balanceQuerier(t, nil, buildIssuanceEntry(testHolderKey, ""))

	_, err := GetSpendingBalance(q, spendingBalanceParams())
	require.ErrorIs(t, err, ErrMPTokenNotFound)
	require.NotErrorIs(t, err, ErrLedgerQuery)
}

func TestGetSpendingBalanceReportsMissingIssuance(t *testing.T) {
	q := balanceQuerier(t, spendingMPToken(unspendableCiphertext), nil)

	_, err := GetSpendingBalance(q, spendingBalanceParams())
	require.ErrorIs(t, err, ErrIssuanceNotFound)
	require.NotErrorIs(t, err, ErrLedgerQuery)
}

func TestGetSpendingBalanceRejectsNonConfidentialIssuance(t *testing.T) {
	issuance := withIssuanceFlags(buildIssuanceEntry(testHolderKey, ""), ledgerentries.LsfMPTCanTransfer)
	q := balanceQuerier(t, spendingMPToken(unspendableCiphertext), issuance)

	_, err := GetSpendingBalance(q, spendingBalanceParams())
	require.ErrorIs(t, err, ErrConfidentialDisabled)
}

// TestGetSpendingBalanceRejectsMalformedLedgerState covers a response that cannot be read
// as the state it claims to be: an entry of the wrong type, and a field present but
// unusable on either entry.
func TestGetSpendingBalanceRejectsMalformedLedgerState(t *testing.T) {
	validIssuance := buildIssuanceEntry(testHolderKey, "")
	validMPToken := spendingMPToken(unspendableCiphertext)

	tests := []struct {
		name     string
		mptoken  ledgerentries.FlatLedgerObject
		issuance ledgerentries.FlatLedgerObject
	}{
		{
			name:     "MPToken index holds another entry type",
			mptoken:  ledgerentries.FlatLedgerObject{"LedgerEntryType": "Offer", "ConfidentialBalanceSpending": unspendableCiphertext},
			issuance: validIssuance,
		},
		{
			name:     "MPToken without an entry type",
			mptoken:  ledgerentries.FlatLedgerObject{"ConfidentialBalanceSpending": unspendableCiphertext},
			issuance: validIssuance,
		},
		{
			name:     "spending ciphertext is not a string",
			mptoken:  ledgerentries.FlatLedgerObject{"LedgerEntryType": string(ledgerentries.MPTokenEntry), "ConfidentialBalanceSpending": float64(1)},
			issuance: validIssuance,
		},
		{
			name:     "spending ciphertext is empty",
			mptoken:  ledgerentries.FlatLedgerObject{"LedgerEntryType": string(ledgerentries.MPTokenEntry), "ConfidentialBalanceSpending": ""},
			issuance: validIssuance,
		},
		{
			name:     "issuance index holds another entry type",
			mptoken:  validMPToken,
			issuance: ledgerentries.FlatLedgerObject{"LedgerEntryType": string(ledgerentries.MPTokenEntry)},
		},
		{
			name:    "issuance flags are not a number",
			mptoken: validMPToken,
			issuance: ledgerentries.FlatLedgerObject{
				"LedgerEntryType": string(ledgerentries.MPTokenIssuanceEntry),
				"Flags":           "1",
			},
		},
		{
			name:    "confidential outstanding amount is not an integer string",
			mptoken: validMPToken,
			issuance: ledgerentries.FlatLedgerObject{
				"LedgerEntryType":               string(ledgerentries.MPTokenIssuanceEntry),
				"Flags":                         float64(confidentialIssuanceFlags),
				"ConfidentialOutstandingAmount": "not-a-number",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			q := balanceQuerier(t, test.mptoken, test.issuance)

			_, err := GetSpendingBalance(q, spendingBalanceParams())
			require.ErrorIs(t, err, ErrInvalidLedgerState)
		})
	}
}

// TestGetSpendingBalanceRejectsUnvalidatedResponse pins that a node answering from state it
// does not report as validated is refused, rather than read as a balance.
func TestGetSpendingBalanceRejectsUnvalidatedResponse(t *testing.T) {
	mptokenIndex, err := xrplhash.MPToken(testIssuanceID, testAccount)
	require.NoError(t, err)
	q := stubEntry(&ledger.EntryResponse{
		Index:       mptokenIndex,
		LedgerHash:  mockLedgerHash,
		LedgerIndex: mockLedgerIndex,
		Node:        spendingMPToken(unspendableCiphertext),
	})

	_, err = GetSpendingBalance(q, spendingBalanceParams())
	require.ErrorIs(t, err, ErrInvalidLedgerState)
}

// TestGetSpendingBalanceRejectsReadsFromTwoLedgers pins the reason both reads go through
// one snapshot. A bound read from a ledger the balance does not belong to could pair a
// balance with a supply that never covered it, which would fail the search or, worse,
// bound it by a supply from before the balance existed.
func TestGetSpendingBalanceRejectsReadsFromTwoLedgers(t *testing.T) {
	const laterLedgerHash = common.LedgerHash("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

	issuanceIndex, err := xrplhash.MPTokenIssuance(testIssuanceID)
	require.NoError(t, err)

	q := ledgerQuerierStub{
		ledgerEntry: func(req *ledger.EntryRequest) (*ledger.EntryResponse, error) {
			resp := &ledger.EntryResponse{
				Index:       req.Index,
				LedgerHash:  mockLedgerHash,
				LedgerIndex: mockLedgerIndex,
				Node:        spendingMPToken(unspendableCiphertext),
				Validated:   true,
			}
			// The issuance is answered from a ledger that closed after the one the MPToken
			// read pinned, which is the straddle the snapshot exists to catch.
			if req.Index == issuanceIndex {
				resp.LedgerHash = laterLedgerHash
				resp.LedgerIndex = mockLedgerIndex + 1
				resp.Node = buildIssuanceEntry(testHolderKey, "")
			}
			return resp, nil
		},
	}

	_, err = GetSpendingBalance(q, spendingBalanceParams())
	require.ErrorIs(t, err, ErrInvalidLedgerState)
}

// TestGetSpendingBalancePreservesQueryErrors pins that a transport failure on either read
// reaches the caller as one, with the node's own error still matchable underneath.
func TestGetSpendingBalancePreservesQueryErrors(t *testing.T) {
	issuanceIndex, err := xrplhash.MPTokenIssuance(testIssuanceID)
	require.NoError(t, err)
	mptokenIndex, err := xrplhash.MPToken(testIssuanceID, testAccount)
	require.NoError(t, err)

	tests := []struct {
		name  string
		index string
	}{
		{name: "MPToken read", index: mptokenIndex},
		{name: "issuance read", index: issuanceIndex},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cause := errors.New("ledger_entry unavailable")
			q := balanceQuerier(t, spendingMPToken(unspendableCiphertext), buildIssuanceEntry(testHolderKey, ""))
			q.entryErrs = map[string]error{test.index: cause}

			_, err := GetSpendingBalance(q, spendingBalanceParams())
			require.ErrorIs(t, err, ErrLedgerQuery)
			require.ErrorIs(t, err, cause)
		})
	}
}

// TestGetSpendingBalancePreservesDecryptionError pins that a ciphertext the ledger carries
// but the decoder cannot read reaches the caller as the elgamal condition it is, and that
// the private key it was decrypted with is nowhere in the message.
func TestGetSpendingBalancePreservesDecryptionError(t *testing.T) {
	q := balanceQuerier(t, spendingMPToken(unspendableCiphertext), buildIssuanceEntry(testHolderKey, ""))

	_, err := GetSpendingBalance(q, spendingBalanceParams())
	require.ErrorIs(t, err, ErrCryptoFailed)
	require.ErrorIs(t, err, elgamal.ErrInvalidCiphertext)
	require.NotContains(t, err.Error(), testHolderPrivKey)
}

// TestGetSpendingBalanceReadsOneValidatedLedgerWithoutAccountQuery pins the two properties
// the read owes its caller: the balance and the supply that bounds it come from one
// validated ledger, and reading a balance never asks for an account sequence, which it
// would spend nothing of.
func TestGetSpendingBalanceReadsOneValidatedLedgerWithoutAccountQuery(t *testing.T) {
	issuanceIndex, err := xrplhash.MPTokenIssuance(testIssuanceID)
	require.NoError(t, err)
	mptokenIndex, err := xrplhash.MPToken(testIssuanceID, testAccount)
	require.NoError(t, err)
	q := balanceQuerier(t, spendingMPToken(unspendableCiphertext), buildIssuanceEntry(testHolderKey, ""))

	// The call fails at the decryption, which is past both reads and the only step this
	// fixture cannot satisfy.
	_, err = GetSpendingBalance(q, spendingBalanceParams())
	require.ErrorIs(t, err, ErrCryptoFailed)

	require.Empty(t, q.accountRequests)
	require.Equal(t, []ledger.EntryRequest{
		// The first read has no ledger to bind to yet, so it asks for the latest validated
		// one and adopts the hash the response reports.
		{Index: mptokenIndex, LedgerIndex: common.LedgerSpecifier(common.Validated)},
		{Index: issuanceIndex, LedgerHash: mockLedgerHash},
	}, q.entryRequests)
}

// TestGetSpendingBalanceRejectsRangeAboveOutstanding pins that a range starting past the
// issuance's whole confidential supply is refused rather than searched, because no holder
// balance can be in it.
func TestGetSpendingBalanceRejectsRangeAboveOutstanding(t *testing.T) {
	const outstanding uint64 = 50

	issuance := buildIssuanceEntry(testHolderKey, "")
	issuance["ConfidentialOutstandingAmount"] = strconv.FormatUint(outstanding, 10)
	q := balanceQuerier(t, spendingMPToken(unspendableCiphertext), issuance)

	params := spendingBalanceParams()
	params.BalanceRange = elgamal.AmountRange{Low: outstanding + 1, High: outstanding + 100}

	_, err := GetSpendingBalance(q, params)
	require.ErrorIs(t, err, elgamal.ErrInvalidAmountRange)
	require.NotErrorIs(t, err, ErrCryptoFailed)
}

// TestBoundedBalanceRangeCapsHighAtOutstanding pins the ceiling every bounded search runs
// under. The confidential supply is the sum of all confidential balances, so a range
// reaching past it only buys search that cannot find anything, and a caller that passed no
// range at all would otherwise search the whole supply.
func TestBoundedBalanceRangeCapsHighAtOutstanding(t *testing.T) {
	const outstanding uint64 = 1000

	tests := []struct {
		name        string
		given       elgamal.AmountRange
		outstanding uint64
		want        elgamal.AmountRange
		wantErr     bool
	}{
		{
			name:        "range within the supply is left alone",
			given:       elgamal.AmountRange{Low: 10, High: 900},
			outstanding: outstanding,
			want:        elgamal.AmountRange{Low: 10, High: 900},
		},
		{
			name:        "high is capped at the supply",
			given:       elgamal.AmountRange{Low: 0, High: outstanding * 1000},
			outstanding: outstanding,
			want:        elgamal.AmountRange{Low: 0, High: outstanding},
		},
		{
			name:        "range ending at the supply is left alone",
			given:       elgamal.AmountRange{Low: 0, High: outstanding},
			outstanding: outstanding,
			want:        elgamal.AmountRange{Low: 0, High: outstanding},
		},
		{
			// An issuance whose confidential supply is zero holds no confidential balance
			// other than an encrypted zero, which the capped range still finds.
			name:        "empty supply caps the search to zero",
			given:       elgamal.AmountRange{Low: 0, High: outstanding},
			outstanding: 0,
			want:        elgamal.AmountRange{Low: 0, High: 0},
		},
		{
			name:        "low above the supply is rejected",
			given:       elgamal.AmountRange{Low: outstanding + 1, High: outstanding + 2},
			outstanding: outstanding,
			wantErr:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := boundedBalanceRange(test.given, test.outstanding)
			if test.wantErr {
				require.ErrorIs(t, err, elgamal.ErrInvalidAmountRange)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}
