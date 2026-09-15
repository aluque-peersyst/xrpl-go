package websocket

import (
	"context"
	"errors"

	clientinternal "github.com/Peersyst/xrpl-go/xrpl/internal/client"
	ledgerentry "github.com/Peersyst/xrpl-go/xrpl/ledger-entry-types"
	ledgerquery "github.com/Peersyst/xrpl-go/xrpl/queries/ledger"
	"github.com/Peersyst/xrpl-go/xrpl/transaction"
	"github.com/Peersyst/xrpl-go/xrpl/transaction/types"
)

// SponsorshipValidation reports the outcome of an online sponsorship preflight.
type SponsorshipValidation = clientinternal.SponsorshipValidation

// ValidateSponsorship checks a sponsored transaction against the Sponsorship
// ledger entry between its sponsor and sponsee, using the current ledger.
//
// The check is explicit and optional: Autofill, SubmitTx, and the other
// submission helpers never perform it. Call it before submitting a sponsored
// transaction to turn a sponsorship problem into a local result instead of a
// rejected submission.
//
// The transaction must carry Sponsor and a nonzero SponsorFlags, and either a
// Fee or a nonempty estimatedFee in drops. The sponsee is the transaction's
// Delegate when present and its Account otherwise.
//
// Without a Sponsorship entry, only a sponsor co-signature (SponsorSignature)
// authorizes the sponsorship. With an entry, its budget always applies, even to
// a co-signed transaction: a sponsored fee must fit within FeeAmount and any
// MaxFee cap, and reserve sponsorship needs at least one RemainingOwnerCount
// unit. Pre-funded use is additionally rejected when the entry sets the matching
// require-signature flag.
//
// The check does not prove the sponsor holds enough XRP for its own account
// reserve, and it counts a single reserve unit, so it does not cover a
// transaction that creates more than one reserved object. rippled remains
// authoritative.
//
// A nil error means the preflight completed; read SponsorshipValidation.Valid
// and SponsorshipValidation.Reason for the outcome. A non-nil error means the
// preflight could not run, because the transaction inputs were unusable or the
// ledger lookup failed.
func (c *Client) ValidateSponsorship(
	tx transaction.FlatTransaction,
	estimatedFee string,
) (SponsorshipValidation, error) {
	return c.ValidateSponsorshipContext(context.Background(), tx, estimatedFee)
}

// ValidateSponsorshipContext is ValidateSponsorship with a caller-supplied
// context governing the ledger_entry lookup.
func (c *Client) ValidateSponsorshipContext(
	ctx context.Context,
	tx transaction.FlatTransaction,
	estimatedFee string,
) (SponsorshipValidation, error) {
	return clientinternal.ValidateSponsorship(tx, estimatedFee,
		func(sponsor, sponsee types.Address) (*ledgerentry.Sponsorship, error) {
			return c.fetchSponsorshipEntry(ctx, sponsor, sponsee)
		},
	)
}

// fetchSponsorshipEntry looks up the Sponsorship entry for a sponsor and
// sponsee. Only rippled's entryNotFound means the pair has no entry. Every other
// failure is returned so a transport, permission, or decoding problem is never
// read as a missing sponsorship.
func (c *Client) fetchSponsorshipEntry(
	ctx context.Context,
	sponsor, sponsee types.Address,
) (*ledgerentry.Sponsorship, error) {
	var response ledgerquery.EntryResponse
	if err := c.requestResult(ctx, clientinternal.SponsorshipEntryRequest(sponsor, sponsee), &response); err != nil {
		if isEntryNotFoundError(err) {
			return nil, nil
		}
		return nil, err
	}
	return clientinternal.DecodeSponsorshipEntry(response.Node)
}

// isEntryNotFoundError reports whether a ledger_entry request failed because the
// ledger has no matching entry.
func isEntryNotFoundError(err error) bool {
	var responseErr *ErrorWebsocketClientXrplResponse
	return errors.As(err, &responseErr) && responseErr.Type == entryNotFound
}
