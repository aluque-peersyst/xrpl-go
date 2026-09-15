package client

import (
	"encoding/json"
	"fmt"

	"github.com/Peersyst/xrpl-go/pkg/typecheck"
	"github.com/Peersyst/xrpl-go/xrpl/currency"
	"github.com/Peersyst/xrpl-go/xrpl/flag"
	ledgerentry "github.com/Peersyst/xrpl-go/xrpl/ledger-entry-types"
	"github.com/Peersyst/xrpl-go/xrpl/queries/common"
	ledgerquery "github.com/Peersyst/xrpl-go/xrpl/queries/ledger"
	"github.com/Peersyst/xrpl-go/xrpl/transaction/types"
)

// SponsorshipValidation reports the outcome of an online sponsorship preflight.
//
// A completed preflight always returns a result. Valid reports whether the
// preflight found a blocking problem, and Reason carries the specific rejection
// when it did. Sponsorship and Fee expose the ledger state and fee the decision
// was made from, so callers can report or re-check them.
type SponsorshipValidation struct {
	// Valid reports whether the preflight found no blocking sponsorship problem.
	Valid bool
	// Reason explains a rejection. It is nil when Valid is true, and otherwise
	// wraps one of the ErrSponsorship* sentinels.
	Reason error
	// Sponsorship is the Sponsorship ledger entry the preflight checked against.
	// It is nil when the sponsor and sponsee have no entry, which a sponsor
	// co-signature alone can authorize.
	Sponsorship *ledgerentry.Sponsorship
	// Fee is the transaction fee, in drops, that the preflight validated.
	Fee currency.Drops
}

// FetchSponsorshipEntry performs the client-specific ledger_entry lookup for the
// Sponsorship entry between a sponsor and a sponsee. It returns a nil entry and
// a nil error when the ledger has no such entry, which rippled reports as
// entryNotFound. Every other failure, including transport, permission, and
// decoding failures, must be returned as an error so the preflight does not
// mistake it for an absent entry.
type FetchSponsorshipEntry func(sponsor, sponsee types.Address) (*ledgerentry.Sponsorship, error)

// SponsorshipEntryRequest builds the ledger_entry request for the Sponsorship
// entry between a sponsor and a sponsee. It reads the current ledger, so a
// sponsorship created moments ago is visible to a preflight.
func SponsorshipEntryRequest(sponsor, sponsee types.Address) *ledgerquery.EntryRequest {
	return &ledgerquery.EntryRequest{
		Sponsorship: ledgerquery.SponsorshipSelector{
			Object: &ledgerquery.SponsorshipSelectorFields{
				Sponsor: sponsor,
				Sponsee: sponsee,
			},
		},
		LedgerIndex: common.Current,
	}
}

// DecodeSponsorshipEntry converts a ledger_entry node into a typed Sponsorship
// entry. It rejects a node of another entry type and a node whose fields do not
// match the Sponsorship wire format, so a decoding failure is never reported as
// a missing entry.
func DecodeSponsorshipEntry(node ledgerentry.FlatLedgerObject) (*ledgerentry.Sponsorship, error) {
	entryType, _ := typecheck.ToString(node["LedgerEntryType"])
	if ledgerentry.EntryType(entryType) != ledgerentry.SponsorshipEntry {
		return nil, fmt.Errorf("%w: got %q", ErrSponsorshipEntryUnexpectedType, entryType)
	}

	encoded, err := json.Marshal(node)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSponsorshipEntryMalformed, err)
	}
	var entry ledgerentry.Sponsorship
	if err := json.Unmarshal(encoded, &entry); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSponsorshipEntryMalformed, err)
	}
	return &entry, nil
}

// ValidateSponsorship runs an online preflight of a sponsored transaction
// against the Sponsorship ledger entry between its sponsor and sponsee. It is an
// explicit, opt-in check: submission and autofill never perform it.
//
// The transaction must carry Sponsor and a nonzero SponsorFlags, and either a
// Fee or a nonempty estimatedFee in drops. The sponsee is the transaction's
// Delegate when present and its Account otherwise, matching how rippled
// resolves the transaction initiator.
//
// Without a Sponsorship entry, a sponsor co-signature (SponsorSignature) is the
// only authorization, so an uncosigned transaction is rejected. With an entry,
// the entry's budget always applies, even to a co-signed transaction, because
// rippled prefers the pre-funded fee payer whenever the entry exists: a sponsored
// fee must fit within FeeAmount and any MaxFee cap, and reserve sponsorship
// needs at least one RemainingOwnerCount unit. Pre-funded use is additionally
// rejected when the entry sets the matching require-signature flag. An entry
// carrying an explicit MaxFee of zero sponsors no fee at all, and a zero fee
// draws nothing from the entry, so it is never rejected for budget.
//
// The check is not a guarantee of success. It does not prove the sponsor holds
// enough XRP for its own account reserve, and it counts a single reserve unit,
// so it does not cover a transaction that creates more than one reserved object,
// as a Vault or a pre-MultiSignReserve SignerList does. It also leaves the shape
// of the sponsored transaction to transaction validation, including the
// SponsorFlags mask, a Sponsor equal to Account, and which transaction types may
// request reserve sponsorship at all. rippled remains authoritative.
//
// A nil error means the preflight ran to completion; read the result for the
// outcome. A non-nil error means it could not run: the transaction inputs were
// unusable, or the ledger lookup failed.
func ValidateSponsorship(
	tx map[string]any,
	estimatedFee string,
	fetchSponsorship FetchSponsorshipEntry,
) (SponsorshipValidation, error) {
	sponsor, sponsorFlags, err := sponsorshipFields(tx)
	if err != nil {
		return SponsorshipValidation{}, err
	}

	fee, err := sponsorshipFee(tx, estimatedFee)
	if err != nil {
		return SponsorshipValidation{}, err
	}

	sponsee, delegated, err := sponsorshipSponsee(tx)
	if err != nil {
		return SponsorshipValidation{}, err
	}

	// rippled rejects reserve sponsorship on a delegated transaction outright, and
	// its reserve check reads the entry between the sponsor and Account rather
	// than the delegate, so no entry can make this combination valid.
	if delegated && flag.Contains(sponsorFlags, types.SpfSponsorReserve) {
		return SponsorshipValidation{Reason: ErrDelegatedReserveSponsorship, Fee: fee}, nil
	}

	entry, err := fetchSponsorship(sponsor, sponsee)
	if err != nil {
		return SponsorshipValidation{}, err
	}

	coSigned := hasSponsorSignature(tx)
	if entry == nil {
		// rippled requires a Sponsorship entry only for pre-funded sponsorship.
		// A sponsor signature is authorization on its own.
		if !coSigned {
			return SponsorshipValidation{
				Reason: fmt.Errorf("%w: sponsor %s, sponsee %s", ErrSponsorshipEntryNotFound, sponsor, sponsee),
				Fee:    fee,
			}, nil
		}
		return SponsorshipValidation{Valid: true, Fee: fee}, nil
	}

	result := SponsorshipValidation{Sponsorship: entry, Fee: fee}
	result.Reason = rejectSponsorship(entry, sponsorFlags, coSigned, fee)
	result.Valid = result.Reason == nil
	return result, nil
}

// rejectSponsorship applies the require-signature flags and the budget of an
// existing Sponsorship entry, returning nil when the entry covers the
// transaction.
func rejectSponsorship(
	entry *ledgerentry.Sponsorship,
	sponsorFlags uint32,
	coSigned bool,
	fee currency.Drops,
) error {
	sponsorsFee := flag.Contains(sponsorFlags, types.SpfSponsorFee)
	sponsorsReserve := flag.Contains(sponsorFlags, types.SpfSponsorReserve)

	if !coSigned {
		if sponsorsFee && flag.Contains(entry.Flags, ledgerentry.LsfSponsorshipRequireSignForFee) {
			return ErrSponsorshipFeeSignatureRequired
		}
		if sponsorsReserve && flag.Contains(entry.Flags, ledgerentry.LsfSponsorshipRequireSignForReserve) {
			return ErrSponsorshipReserveSignatureRequired
		}
	}

	// A Sponsorship entry's budget binds every sponsored transaction, including
	// one the sponsor also co-signs.
	if sponsorsReserve && (entry.RemainingOwnerCount == nil || *entry.RemainingOwnerCount < 1) {
		return fmt.Errorf("%w: RemainingOwnerCount %s", ErrSponsorshipReserveBudgetExhausted, ownerCountText(entry.RemainingOwnerCount))
	}

	// rippled returns early before it resolves a fee payer when the transaction
	// pays no fee, so a zero fee draws nothing from the entry.
	if !sponsorsFee || fee.Cmp(currency.DropsFromUint64(0)) == 0 {
		return nil
	}

	if entry.FeeAmount == nil {
		return ErrSponsorshipFeeAmountMissing
	}
	feeAmount := currency.DropsFromUint64(entry.FeeAmount.Uint64())
	if feeAmount.Cmp(fee) < 0 {
		return fmt.Errorf("%w: FeeAmount %s drops, fee %s drops", ErrSponsorshipFeeBudgetExhausted, entry.FeeAmount, dropsText(fee))
	}

	if entry.MaxFee != nil {
		maxFee := currency.DropsFromUint64(entry.MaxFee.Uint64())
		if fee.Cmp(maxFee) > 0 {
			return fmt.Errorf("%w: MaxFee %s drops, fee %s drops", ErrSponsorshipMaxFeeExceeded, entry.MaxFee, dropsText(fee))
		}
	}

	return nil
}

// sponsorshipFields reads the sponsored-transaction common fields that identify
// the sponsor and the requested sponsorship types.
func sponsorshipFields(tx map[string]any) (types.Address, uint32, error) {
	sponsorValue, hasSponsor := tx["Sponsor"]
	flagsValue, hasFlags := tx["SponsorFlags"]
	if !hasSponsor || !hasFlags {
		return "", 0, ErrTransactionNotSponsored
	}

	sponsor, ok := typecheck.ToString(sponsorValue)
	if !ok {
		return "", 0, fmt.Errorf("%w: got %T", ErrSponsorFieldIsNotAString, sponsorValue)
	}
	sponsorFlags, ok := typecheck.ToUint32(flagsValue)
	if !ok {
		return "", 0, fmt.Errorf("%w: got %T", ErrSponsorFlagsFieldIsNotAUint32, flagsValue)
	}
	if sponsor == "" || sponsorFlags == 0 {
		return "", 0, ErrTransactionNotSponsored
	}

	return types.Address(sponsor), sponsorFlags, nil
}

// sponsorshipSponsee resolves the account whose sponsorship is being used, and
// reports whether a Delegate supplied it. rippled looks up the Sponsorship entry
// against the transaction initiator, which is Delegate for a delegated
// transaction and Account otherwise.
func sponsorshipSponsee(tx map[string]any) (types.Address, bool, error) {
	for _, field := range []string{"Delegate", "Account"} {
		value, exists := tx[field]
		if !exists || value == nil {
			continue
		}
		account, ok := typecheck.ToString(value)
		if !ok {
			return "", false, fmt.Errorf("%w: field %s is a %T", ErrAddressFieldIsNotAString, field, value)
		}
		if account != "" {
			return types.Address(account), field == "Delegate", nil
		}
	}
	return "", false, ErrSponsorshipSponseeUnavailable
}

// hasSponsorSignature reports whether the transaction carries a sponsor
// co-signature. A present but nil SponsorSignature is not authorization.
func hasSponsorSignature(tx map[string]any) bool {
	switch signature := tx["SponsorSignature"].(type) {
	case nil:
		return false
	case map[string]any:
		return signature != nil
	default:
		return true
	}
}

// sponsorshipFee prefers an explicitly supplied estimate over the transaction's
// own Fee, so a preflight can run before autofill has set one.
func sponsorshipFee(tx map[string]any, estimatedFee string) (currency.Drops, error) {
	feeText := estimatedFee
	if feeText == "" {
		value, exists := tx["Fee"]
		if !exists || value == nil {
			return currency.Drops{}, ErrSponsorshipFeeUnavailable
		}
		text, ok := typecheck.ToString(value)
		if !ok {
			return currency.Drops{}, fmt.Errorf("%w: got %T", ErrSponsorshipFeeIsNotAString, value)
		}
		if text == "" {
			return currency.Drops{}, ErrSponsorshipFeeUnavailable
		}
		feeText = text
	}

	fee, err := currency.DropsFromString(feeText)
	if err != nil {
		return currency.Drops{}, fmt.Errorf("%w: %q: %w", ErrInvalidSponsorshipFee, feeText, err)
	}
	return fee, nil
}

func dropsText(drops currency.Drops) string {
	text, err := drops.WholeString()
	if err != nil {
		return "unknown"
	}
	return text
}

func ownerCountText(remaining *uint32) string {
	if remaining == nil {
		return "absent"
	}
	return fmt.Sprintf("%d", *remaining)
}
