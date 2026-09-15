package builder

import (
	"fmt"

	"github.com/Peersyst/xrpl-go/confidential/elgamal"
)

// SpendingBalanceParams holds the inputs for GetSpendingBalance.
type SpendingBalanceParams struct {
	// Holder is the account whose balance is read, in either address form. A tagged
	// X-address resolves to the account it encodes and the tag is ignored, because an
	// MPToken is held per account and carries no tag of its own.
	Holder string
	// IssuanceID is the 48 hex character MPTokenIssuanceID the balance belongs to.
	IssuanceID string
	// HolderPrivKey is the holder's ElGamal private key, a non-zero secp256k1 scalar below
	// the curve order. It never reaches the ledger, and no error this helper returns
	// reproduces it.
	HolderPrivKey string
	// BalanceRange bounds the decryption search. The bounds are inclusive and the search
	// cost is linear, so the narrowest range the caller can justify is the right one. It is
	// required rather than defaulted, because the only bound this package could infer is
	// the issuance's whole confidential supply, which is as large as the issuance is.
	BalanceRange elgamal.AmountRange
}

// GetSpendingBalance reads a holder's confidential spending balance from the ledger and
// returns it in plaintext. It is the read-only counterpart to the Build* helpers, and the
// equivalent of xrpl.js's getConfidentialBalance: the ledger stores ciphertexts, so only
// the holder's own ElGamal private key turns one back into an amount.
//
// The inbox is deliberately not included. XLS-96 credits an incoming send to
// ConfidentialBalanceInbox, which no transaction can spend until a
// ConfidentialMPTMergeInbox moves it into ConfidentialBalanceSpending, so counting it here
// would report a balance the holder cannot yet send or convert back.
//
// Both reads are pinned to one validated ledger, so the bound the search runs under can
// never come from an earlier ledger than the balance it must cover. The MPToken is read
// first and a missing one aborts, which is what selects that ledger for the issuance read
// that follows. An MPToken that exists but carries no spending ciphertext returns zero
// without reading the issuance at all: the holder has not converted yet, or converted only
// into an inbox not yet merged.
//
// Decryption needs the native backend, so a CGO_ENABLED=0 build reaches
// mptcrypto.ErrCgoRequired here, wrapped in ErrCryptoFailed. The zero-balance path above
// returns before any cryptographic work and is the one case that answers without it.
//
// Errors: ErrMPTokenNotFound when the holder holds no MPToken for the issuance,
// ErrIssuanceNotFound when the issuance itself is gone, ErrLedgerQuery for a transport
// failure, ErrInvalidLedgerState for a response that is malformed or read from another
// ledger, and ErrCryptoFailed when the balance is not inside the search range.
func GetSpendingBalance(q LedgerQuerier, p SpendingBalanceParams) (uint64, error) {
	if err := validateSpendingBalanceParams(p); err != nil {
		return 0, err
	}

	// Reading a balance spends no sequence and binds no proof, so no account query is made
	// and the snapshot starts unbound: the MPToken read below selects the validated ledger
	// every later read of this call is bound to.
	snapshot := &ledgerSnapshot{q: q}

	resp, err := getMPTokenEntry(snapshot, p.IssuanceID, p.Holder)
	if err != nil {
		return 0, err
	}
	// A holder that never converted has no ConfidentialBalanceSpending, and rippled omits
	// the field rather than writing an empty blob, so an absent value is a zero balance and
	// only a present but unreadable one is malformed.
	balanceCt, err := optionalString(resp.Node, "ConfidentialBalanceSpending")
	if err != nil {
		return 0, err
	}
	if balanceCt == "" {
		return 0, nil
	}

	// The issuance is read for its confidential supply, which bounds every holder balance
	// and so tightens the caller's search range. readIssuance also rejects an issuance that
	// cannot hold confidential balances at all.
	issuance, err := readIssuance(snapshot, p.IssuanceID)
	if err != nil {
		return 0, err
	}
	searchRange, err := boundedBalanceRange(p.BalanceRange, issuance.confidentialOutstanding)
	if err != nil {
		return 0, err
	}

	balance, err := elgamal.Decrypt(balanceCt, p.HolderPrivKey, searchRange)
	if err != nil {
		return 0, fmt.Errorf("%w: failed to decrypt spending balance: %w", ErrCryptoFailed, err)
	}
	return balance, nil
}

// validateSpendingBalanceParams rejects inputs that can never resolve a balance, before any
// ledger query. The issuer is rejected along with a malformed issuance ID, because XLS-96
// forbids an issuer from holding its own issuance confidentially, so it has no MPToken to
// read and no spending balance to decrypt.
func validateSpendingBalanceParams(p SpendingBalanceParams) error {
	if p.Holder == "" {
		return ErrMissingHolder
	}
	if _, err := decodeBuilderAddress(p.Holder); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidHolder, err)
	}
	if p.IssuanceID == "" {
		return ErrMissingIssuanceID
	}
	if err := validateHolderRole(p.IssuanceID, p.Holder); err != nil {
		return err
	}
	if p.HolderPrivKey == "" {
		return ErrMissingHolderKey
	}
	if !isValidPrivateKey(p.HolderPrivKey) {
		return ErrInvalidPrivKey
	}
	return p.BalanceRange.Validate()
}

// boundedBalanceRange narrows a caller's decryption range to the issuance's confidential
// supply, which is the sum of every confidential balance and so an upper bound on any one
// of them. Decryption cost is linear in the range, so a range reaching past the supply only
// buys search that cannot find anything.
//
// The caller's own Low is not moved. A range that starts above the supply cannot contain
// the balance at all, and that is a problem with the bounds supplied rather than the
// protocol condition ErrAmountExceedsOutstanding reports, so it is reported as an invalid
// range instead.
func boundedBalanceRange(searchRange elgamal.AmountRange, confidentialOutstanding uint64) (elgamal.AmountRange, error) {
	if searchRange.Low > confidentialOutstanding {
		return elgamal.AmountRange{}, fmt.Errorf("%w: BalanceRange.Low %d exceeds the issuance confidential outstanding amount %d",
			elgamal.ErrInvalidAmountRange, searchRange.Low, confidentialOutstanding)
	}
	if searchRange.High > confidentialOutstanding {
		searchRange.High = confidentialOutstanding
	}
	return searchRange, nil
}
