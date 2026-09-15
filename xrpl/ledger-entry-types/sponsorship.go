package ledger

import "github.com/Peersyst/xrpl-go/xrpl/transaction/types"

// Sponsorship ledger entry flags.
const (
	// LsfSponsorshipRequireSignForFee requires a sponsor signature on every
	// transaction where this sponsorship pays the transaction fee.
	LsfSponsorshipRequireSignForFee uint32 = 0x00010000
	// LsfSponsorshipRequireSignForReserve requires a sponsor signature on every
	// transaction where this sponsorship pays an object or account reserve.
	LsfSponsorshipRequireSignForReserve uint32 = 0x00020000
)

// Sponsorship entry type represents a pre-funded sponsoring relationship between a
// sponsor (Owner) and a sponsee. The entry lets a sponsor fund fees and reserves
// without co-signing every sponsored transaction, and caps how much of either the
// sponsee may consume. (Requires the Sponsorship amendment, XLS-68)
//
// ```json
//
//	{
//	  "LedgerEntryType": "Sponsorship",
//	  "Owner": "rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH",
//	  "Sponsee": "rGWrZyQqhTp9Xu7G5Pkayo7bXjH4k4QYpf",
//	  "FeeAmount": "1000000",
//	  "MaxFee": "1000",
//	  "RemainingOwnerCount": 5,
//	  "Flags": 0,
//	  "OwnerNode": "0000000000000000",
//	  "SponseeNode": "0000000000000000",
//	  "PreviousTxnID": "F19AD4577212D3BEACA0F75FE1BA1644F2E854D46E8D62E9C95D18E9708CBFB1",
//	  "PreviousTxnLgrSeq": 12345678
//	}
//
// ```
type Sponsorship struct {
	// The unique ID for this ledger entry. In JSON, this field is represented with different names depending on the
	// context and API method. (Note, even though this is specified as "optional" in the code, every ledger entry
	// should have one unless it's legacy data from very early in the XRP Ledger's history.)
	Index types.Hash256 `json:"index,omitempty"`
	// The type of ledger entry. Always "Sponsorship" for this entry type.
	LedgerEntryType EntryType
	// A bit-map of boolean flags. Valid flags are LsfSponsorshipRequireSignForFee
	// and LsfSponsorshipRequireSignForReserve.
	Flags uint32
	// The sponsor associated with this relationship. This account also pays the reserve of this entry.
	Owner types.Address
	// The sponsee associated with this relationship.
	Sponsee types.Address
	// The remaining amount of XRP, in drops, that the sponsor has provided for the sponsee to use for fees.
	FeeAmount *types.XRPCurrencyAmount `json:",omitempty"`
	// The maximum fee, in drops, that is sponsored per transaction. Absent means no per-transaction cap.
	MaxFee *types.XRPCurrencyAmount `json:",omitempty"`
	// The remaining number of owner count units that the sponsor has provided for the sponsee to use for reserves.
	RemainingOwnerCount *uint32 `json:",omitempty"`
	// A hint indicating which page of the sponsor's owner directory links to this entry,
	// in case the directory consists of multiple pages.
	OwnerNode string
	// A hint indicating which page of the sponsee's owner directory links to this entry,
	// in case the directory consists of multiple pages.
	SponseeNode string
	// The identifying hash of the transaction that most recently modified this entry.
	PreviousTxnID types.Hash256
	// The index of the ledger that contains the transaction that most recently modified this entry.
	PreviousTxnLgrSeq uint32
}

// EntryType returns the type of the ledger entry.
func (*Sponsorship) EntryType() EntryType {
	return SponsorshipEntry
}
