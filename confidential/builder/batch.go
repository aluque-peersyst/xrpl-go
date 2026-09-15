package builder

import (
	"fmt"
	"strings"

	"github.com/Peersyst/xrpl-go/xrpl/queries/common"
	"github.com/Peersyst/xrpl-go/xrpl/transaction"
	"github.com/Peersyst/xrpl-go/xrpl/transaction/types"
)

// batchInnerBounds are the inner counts rippled accepts in a Batch. They are the same
// bounds transaction.Batch validates against, checked here first so a rejected size costs
// no ledger reads and no proof generation.
const (
	minBatchOperations = 2
	maxBatchOperations = 8
)

// BatchOperation is one ordered inner of a confidential Batch. The five confidential
// operations each wrap the parameters of the standalone builder they mirror, so an inner
// reads the same as the call it replaces, and a ready-made ordinary transaction is carried
// by TransactionOp. The interface is closed: only the types in this package implement it.
type BatchOperation interface {
	// batchOperation seals the interface to this package.
	batchOperation()
}

// ConvertOp moves public MPT into a confidential balance, as BuildConvert does. The
// assembler decides for itself whether the operation registers the holder's encryption key,
// from the key the predicted state carries rather than from the ledger, so a second convert
// for one holder in a Batch does not try to register a key the first one already did.
type ConvertOp struct {
	BuildConvertParams
}

// ConvertBackOp reveals part of a confidential balance as public MPT, as BuildConvertBack
// does. Its proof binds the spending balance and the version the predicted state carries.
type ConvertBackOp struct {
	BuildConvertBackParams
}

// SendOp transfers a confidential amount to another holder, as BuildSend does. Its proof
// binds the sender's predicted spending balance and version, and it encrypts to the
// destination key the predicted state carries, which an earlier convert in the same Batch
// may have registered.
type SendOp struct {
	BuildSendParams
}

// MergeInboxOp folds a holder's inbox into its spending balance, as BuildMergeInbox does.
// It carries no proof, so nothing binds it to a nonce, but it resets the inbox to a value
// this package cannot reproduce: it must be the last operation on its MPToken in a Batch.
type MergeInboxOp struct {
	BuildMergeInboxParams
}

// ClawbackOp burns a holder's entire confidential balance, as BuildClawback does. The
// amount is decrypted from the predicted issuer mirror balance, so a clawback sees what
// earlier inners of the same Batch left the holder. It resets every balance of that holder,
// so it must be the last operation on the holder's MPToken in a Batch.
type ClawbackOp struct {
	BuildClawbackParams
}

// TransactionOp carries a ready-made ordinary transaction as an inner. The assembler only
// shapes it as a Batch inner and, when it carries neither nonce of its own, assigns it a
// sequence; it builds nothing and reads nothing from it beyond that.
//
// Only the transaction types in SupportedInnerTransactionTypes are accepted. Anything that
// could change a confidential balance, an MPToken's existence, or an issuance is refused,
// because the assembler would have to predict its effect to keep the later proofs valid.
type TransactionOp struct {
	Tx BatchInnerTransaction
}

// BatchInnerTransaction is the contract a ready-made inner must meet. Every transaction
// type in xrpl/transaction satisfies it through its pointer type.
type BatchInnerTransaction interface {
	TxType() transaction.TxType
	Flatten() transaction.FlatTransaction
	Validate() (bool, error)
}

func (ConvertOp) batchOperation()     {}
func (ConvertBackOp) batchOperation() {}
func (SendOp) batchOperation()        {}
func (MergeInboxOp) batchOperation()  {}
func (ClawbackOp) batchOperation()    {}
func (TransactionOp) batchOperation() {}

// BuildBatchParams holds the inputs for BuildBatch.
type BuildBatchParams struct {
	// TxOptions carries the outer Batch's own nonce. Left zero, the account sequence is
	// read from the ledger. A Ticket may be spent instead, in which case the account's own
	// inners start at its current sequence rather than one past the outer Batch's.
	//
	// Batch is not delegatable, so a non-empty Delegate is rejected.
	TxOptions
	// Account owns the outer Batch: it pays the fee, it signs, and its sequence or ticket
	// the Batch spends.
	Account string
	// Operations are the inner transactions in the order the ledger applies them. The
	// order is what the predictions are threaded along, so it is the caller's statement of
	// intent and never reordered. A Batch holds between two and eight.
	Operations []BatchOperation
	// Flags select the outer Batch mode. Zero means transaction.TfAllOrNothing, the only
	// mode whose apply order the assembler can predict.
	Flags uint32
}

// BuildBatch assembles an ordered Batch of confidential MPT operations. It is the one
// builder here that exists because calling the others cannot work: each standalone builder
// reads the ledger, and inside a Batch the ledger does not yet show what an earlier inner
// leaves behind, so proofs built that way bind balances and versions the transaction will
// no longer find when it applies.
//
// # What the assembler owns
//
//   - One validated ledger. Every MPToken and issuance the Batch touches is read from a
//     single snapshot, so no inner's proof mixes state from two ledgers.
//   - Predicted state. A map keyed by decoded holder AccountID and issuance ID carries the
//     spending and inbox ciphertexts, the issuer and auditor mirror balances, the holder
//     keys, the balance versions, and the public amounts, advanced after each inner exactly
//     as the transactor advances them.
//   - Final nonces. Every inner's sequence, or the ticket it spends instead, is resolved
//     before any proof is generated, because a confidential context hash commits to the
//     nonce and no later autofill can repair a proof.
//   - Inner shape. Each inner carries the inner-Batch flag, a zero Fee, an empty
//     SigningPubKey, and no individual signature, as XLS-56 requires.
//
// # What the caller owns
//
// Fee and LastLedgerSequence are left unset, so the returned Batch goes through the
// client's own autofill, which prices a Batch by summing its inners and charges each
// confidential inner the multiplier rippled applies. Autofill cannot disturb a proof: every
// nonce the proofs bind is already set, and autofill assigns only nonces that are missing.
//
// Signing is also the caller's: each participating account signs with
// wallet.SignMultiBatch, the signatures are merged with wallet.CombineBatchSigners, and the
// outer account signs the Batch itself.
//
// # Limits
//
// The assembler refuses to emit a proof it can already tell the ledger will reject, and
// each refusal has a sentinel:
//
//   - Only the all-or-nothing mode is supported (ErrBatchModeNotSupported). Under any other
//     mode an inner can be skipped or fail while later inners still apply, and every
//     prediction after it would be wrong.
//   - A later inner cannot read a balance value an earlier inner left as the canonical
//     encrypted zero (ErrBatchUnpredictableState). The transactor derives that ciphertext
//     from the holder key, the account and the issuance, and this package does not, so the
//     three inners that produce one hand the rest of the Batch a balance it cannot name: a
//     merge leaves the inbox that way, a clawback leaves all four balances of its holder
//     that way, and a holder's first convert leaves its spending balance that way. Only an
//     inner that reads the value is refused; one that needs the field merely to exist, as a
//     send's destination and a merge do, still builds. In practice that means a holder can
//     receive after a merge and merge after a first convert, but cannot spend from a balance
//     any of the three left behind: split that across Batches.
//   - A ready-made inner is accepted only from the set of ordinary transaction types that
//     cannot change confidential state, MPToken existence, or an issuance
//     (ErrBatchInnerNotSupported). Opting a holder in, authorizing one, or moving public
//     MPT belongs before the Batch, not inside it.
//   - A confidential operation may not carry its own Sequence (ErrBatchInnerSequenceSet),
//     because the assembler derives every inner sequence from its position. A Ticket is
//     accepted, and the proof binds it in place of the sequence.
func BuildBatch(q LedgerQuerier, p BuildBatchParams) (*transaction.Batch, error) {
	if err := validateBatchParams(p); err != nil {
		return nil, err
	}

	resolved, snapshot, err := resolveTxOptions(q, p.Account, p.TxOptions, transaction.BatchTx)
	if err != nil {
		return nil, err
	}
	p.TxOptions = resolved

	nonces, err := loadBatchSequences(q, p)
	if err != nil {
		return nil, err
	}
	state, err := loadBatchState(snapshot, p.Operations)
	if err != nil {
		return nil, err
	}

	rawTransactions := make([]types.RawTransaction, 0, len(p.Operations))
	for index, operation := range p.Operations {
		inner, err := buildBatchInner(state, nonces, operation)
		if err != nil {
			return nil, fmt.Errorf("operation %d: %w", index, err)
		}
		rawTransactions = append(rawTransactions, types.RawTransaction{RawTransaction: inner})
	}

	batch := &transaction.Batch{
		BaseTx:          baseTx(p.Account, transaction.BatchTx, p.TxOptions),
		RawTransactions: rawTransactions,
	}
	batch.Flags = batchFlags(p.Flags)

	if err := validatePreparedTransaction(batch); err != nil {
		return nil, err
	}
	return batch, nil
}

// batchFlags resolves the outer mode, defaulting an unset value to all-or-nothing.
func batchFlags(flags uint32) uint32 {
	if flags == 0 {
		return transaction.TfAllOrNothing
	}
	return flags
}

// validateBatchParams rejects what the assembler can decide before any ledger access: the
// outer account, the inner count, the mode, and the shape of each operation.
func validateBatchParams(p BuildBatchParams) error {
	if p.Account == "" {
		return ErrMissingAccount
	}
	if _, err := decodeBuilderAddress(p.Account); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAccount, err)
	}
	if count := len(p.Operations); count < minBatchOperations || count > maxBatchOperations {
		return fmt.Errorf("%w: a Batch holds between %d and %d inner transactions, got %d",
			ErrBatchOperationCount, minBatchOperations, maxBatchOperations, count)
	}
	// Every other mode lets an inner be skipped or fail while later inners still apply, and
	// each prediction after that point would describe a ledger that never happened.
	if flags := batchFlags(p.Flags); flags != transaction.TfAllOrNothing {
		return fmt.Errorf("%w: only tfAllOrNothing (%#x) is supported, got %#x",
			ErrBatchModeNotSupported, transaction.TfAllOrNothing, flags)
	}

	for index, operation := range p.Operations {
		if err := validateBatchOperation(operation); err != nil {
			return fmt.Errorf("operation %d: %w", index, err)
		}
	}
	return nil
}

// validateBatchOperation rejects an operation the assembler cannot own the nonce of, and a
// ready-made inner whose effect it cannot predict.
func validateBatchOperation(operation BatchOperation) error {
	if operation == nil {
		return ErrBatchMissingOperation
	}
	if plain, ok := operation.(TransactionOp); ok {
		return validatePlainInner(plain)
	}
	options, err := operationOptions(operation)
	if err != nil {
		return err
	}
	// The assembler derives each inner sequence from the operation's position, so a caller
	// that also sets one is describing an order the assembler cannot honor. A Ticket is a
	// nonce the account allocated in advance and carries no position, so it is accepted and
	// the proof binds it.
	if options.Sequence != 0 {
		return ErrBatchInnerSequenceSet
	}
	return nil
}

// operationAccount reports the account whose nonce an operation spends. For a clawback that
// is the issuer, not the holder whose balance it burns.
func operationAccount(operation BatchOperation) (string, error) {
	switch op := operation.(type) {
	case ConvertOp:
		return op.Account, nil
	case ConvertBackOp:
		return op.Account, nil
	case SendOp:
		return op.Account, nil
	case MergeInboxOp:
		return op.Account, nil
	case ClawbackOp:
		return op.Account, nil
	case TransactionOp:
		return plainInnerAccount(op)
	default:
		return "", fmt.Errorf("%w: %T", ErrBatchInnerNotSupported, operation)
	}
}

// operationOptions reports the nonce options a confidential operation carries.
func operationOptions(operation BatchOperation) (TxOptions, error) {
	switch op := operation.(type) {
	case ConvertOp:
		return op.TxOptions, nil
	case ConvertBackOp:
		return op.TxOptions, nil
	case SendOp:
		return op.TxOptions, nil
	case MergeInboxOp:
		return op.TxOptions, nil
	case ClawbackOp:
		return op.TxOptions, nil
	default:
		return TxOptions{}, fmt.Errorf("%w: %T", ErrBatchInnerNotSupported, operation)
	}
}

// operationCarriesNonce reports whether an inner already has a nonce of its own, and so
// takes no sequence from its account's counter. A confidential operation has one when it
// spends a Ticket; a ready-made inner has one when the caller set either nonce on it.
func operationCarriesNonce(operation BatchOperation) (bool, error) {
	if plain, ok := operation.(TransactionOp); ok {
		if plain.Tx == nil {
			return false, ErrBatchMissingOperation
		}
		return plainInnerHasNonce(plain.Tx.Flatten()), nil
	}
	options, err := operationOptions(operation)
	if err != nil {
		return false, err
	}
	return options.TicketSequence != 0, nil
}

// batchNonces allocates each inner its sequence. An account's inners take consecutive
// sequences from the one it will next spend, which for the outer Batch account is one past
// the sequence the Batch itself spends. An inner that spends a Ticket takes none.
type batchNonces struct {
	next map[string]uint32
}

// allocate consumes an account's next sequence, or reports that the inner spends a Ticket
// and needs none.
func (n *batchNonces) allocate(account string, options TxOptions) (uint32, error) {
	if options.TicketSequence != 0 {
		return 0, nil
	}
	decoded, err := decodeBuilderAddress(account)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidAccount, err)
	}
	sequence, ok := n.next[decoded.Classic]
	if !ok {
		return 0, fmt.Errorf("%w: no sequence resolved for %s", ErrInvalidLedgerState, decoded.Classic)
	}
	n.next[decoded.Classic] = sequence + 1
	return sequence, nil
}

// loadBatchSequences resolves the first sequence each inner account will spend. Sequences
// come from the open ledger, which counts everything the account already submitted, and are
// deliberately not read from the validated snapshot the proofs are built against: a proof
// must bind the nonce the transaction is applied with, which is a fact about the future
// rather than about the ledger the state came from.
func loadBatchSequences(q LedgerQuerier, p BuildBatchParams) (*batchNonces, error) {
	batchAccount, err := decodeBuilderAddress(p.Account)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidAccount, err)
	}

	nonces := &batchNonces{next: make(map[string]uint32, len(p.Operations)+1)}
	for _, operation := range p.Operations {
		ownNonce, err := operationCarriesNonce(operation)
		if err != nil {
			return nil, err
		}
		if ownNonce {
			continue
		}
		account, err := operationAccount(operation)
		if err != nil {
			return nil, err
		}
		decoded, err := decodeBuilderAddress(account)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidAccount, err)
		}
		if _, loaded := nonces.next[decoded.Classic]; loaded {
			continue
		}

		// The outer Batch spends the account's current sequence, so its own inners start one
		// past it. That is already in hand and needs no second query. A Batch spending a
		// Ticket leaves the account sequence untouched, so its inners start at it.
		if decoded.Classic == batchAccount.Classic && p.Sequence != 0 {
			nonces.next[decoded.Classic] = p.Sequence + 1
			continue
		}
		sequence, err := currentAccountSequence(q, decoded.Classic)
		if err != nil {
			return nil, err
		}
		nonces.next[decoded.Classic] = sequence
	}
	return nonces, nil
}

// currentAccountSequence reads the sequence an account will next spend from the open ledger.
func currentAccountSequence(q LedgerQuerier, classic string) (uint32, error) {
	info, err := getAccountInfo(q, types.Address(classic), common.Current)
	if err != nil {
		return 0, err
	}
	// An account that exists always has a sequence of at least 1, so a zero means
	// account_info answered about something no inner can be signed for.
	if info.AccountData.Sequence == 0 {
		return 0, fmt.Errorf("%w: account_info reported sequence 0 for %s", ErrInvalidLedgerState, classic)
	}
	return info.AccountData.Sequence, nil
}

// loadBatchState reads the initial state of every issuance and MPToken the operations
// reference, all from one validated ledger. Issuances are read first, so the snapshot a
// caller-supplied nonce left unbound is selected by a read whose failure aborts the build.
func loadBatchState(snapshot *ledgerSnapshot, operations []BatchOperation) (*batchState, error) {
	state := &batchState{
		tokens:    make(map[tokenKey]*tokenState, len(operations)),
		issuances: make(map[string]*batchIssuance, len(operations)),
	}

	// A token referenced only by clawbacks skips the locked and authorized checks, which
	// the clawback transactor deliberately does not make, so a holder the issuer locked can
	// still be clawed back from. Any other reference reinstates them.
	usable := make(map[tokenKey]bool)
	// An issuance every operation merely merges on needs no issuer key, because a merge
	// encrypts nothing. Anything else does.
	provable := make(map[string]bool)

	type reference struct {
		key    tokenKey
		holder string
	}
	// Both lists keep the order the operations first named each entry, so a Batch with two
	// unreadable entries fails on the earlier operation's rather than on whichever one a map
	// happened to yield first.
	issuanceIDs := make([]string, 0, len(operations))
	references := make([]reference, 0, len(operations)+1)
	for _, operation := range operations {
		issuanceID, holders, err := operationReferences(operation)
		if err != nil {
			return nil, err
		}
		if issuanceID == "" {
			continue
		}
		normalized := strings.ToUpper(issuanceID)
		if _, seen := provable[normalized]; !seen {
			provable[normalized] = false
			issuanceIDs = append(issuanceIDs, normalized)
		}
		if _, isMerge := operation.(MergeInboxOp); !isMerge {
			provable[normalized] = true
		}

		_, isClawback := operation.(ClawbackOp)
		for _, holder := range holders {
			key, err := newTokenKey(holder, issuanceID)
			if err != nil {
				return nil, err
			}
			if _, seen := usable[key]; !seen {
				references = append(references, reference{key: key, holder: holder})
			}
			usable[key] = usable[key] || !isClawback
		}
	}

	for _, issuanceID := range issuanceIDs {
		issuance, err := readBatchIssuance(snapshot, issuanceID, provable[issuanceID])
		if err != nil {
			return nil, fmt.Errorf("issuance %s: %w", issuanceID, err)
		}
		state.issuances[issuanceID] = issuance
	}
	for _, ref := range references {
		issuance, err := state.issuance(ref.key.issuance)
		if err != nil {
			return nil, err
		}
		token, err := readBatchTokenState(snapshot, issuance.issuanceState, ref.key, ref.holder, usable[ref.key])
		if err != nil {
			// A Batch reads several MPTokens before it builds anything, so a condition the
			// standalone builders can attribute to "the sender" or "the destination" is named
			// by the holder and issuance it belongs to instead.
			return nil, fmt.Errorf("%s: %w", ref.key, err)
		}
		state.tokens[ref.key] = token
	}
	return state, nil
}

// readBatchIssuance reads one issuance and seeds its running confidential supply.
func readBatchIssuance(snapshot *ledgerSnapshot, issuanceID string, needsIssuerKey bool) (*batchIssuance, error) {
	read := readIssuance
	if needsIssuerKey {
		read = getProvableIssuance
	}
	issuance, err := read(snapshot, issuanceID)
	if err != nil {
		return nil, err
	}
	return &batchIssuance{issuanceState: issuance, outstanding: issuance.confidentialOutstanding}, nil
}

// operationReferences reports the issuance an operation acts on and the holders whose
// MPToken state it reads or writes. A ready-made inner references neither, because the
// assembler accepts only types that cannot touch confidential state.
func operationReferences(operation BatchOperation) (string, []string, error) {
	switch op := operation.(type) {
	case ConvertOp:
		return op.IssuanceID, []string{op.Account}, nil
	case ConvertBackOp:
		return op.IssuanceID, []string{op.Account}, nil
	case SendOp:
		return op.IssuanceID, []string{op.Account, op.Destination}, nil
	case MergeInboxOp:
		return op.IssuanceID, []string{op.Account}, nil
	case ClawbackOp:
		// The issuer holds no MPToken of its own issuance, so only the holder's is read.
		return op.IssuanceID, []string{op.Holder}, nil
	case TransactionOp:
		return "", nil, nil
	default:
		return "", nil, fmt.Errorf("%w: %T", ErrBatchInnerNotSupported, operation)
	}
}

// buildBatchInner builds one inner against the current predictions, advances them by what
// that inner does, and returns the inner shaped for a Batch.
func buildBatchInner(state *batchState, nonces *batchNonces, operation BatchOperation) (transaction.FlatTransaction, error) {
	if plain, ok := operation.(TransactionOp); ok {
		return buildPlainInner(nonces, plain)
	}

	account, err := operationAccount(operation)
	if err != nil {
		return nil, err
	}
	options, err := operationOptions(operation)
	if err != nil {
		return nil, err
	}
	sequence, err := nonces.allocate(account, options)
	if err != nil {
		return nil, err
	}
	options.Sequence = sequence

	tx, err := prepareBatchOperation(state, operation, options)
	if err != nil {
		return nil, err
	}
	return shapeBatchInner(tx), nil
}

// prepareBatchOperation dispatches to the Prepare helper of the operation's own builder,
// feeding it the predicted state in place of the ledger reads the Build helper would make,
// and then advances the predictions.
func prepareBatchOperation(state *batchState, operation BatchOperation, options TxOptions) (BatchInnerTransaction, error) {
	switch op := operation.(type) {
	case ConvertOp:
		return prepareBatchConvert(state, op, options)
	case ConvertBackOp:
		return prepareBatchConvertBack(state, op, options)
	case SendOp:
		return prepareBatchSend(state, op, options)
	case MergeInboxOp:
		return prepareBatchMergeInbox(state, op, options)
	case ClawbackOp:
		return prepareBatchClawback(state, op, options)
	default:
		return nil, fmt.Errorf("%w: %T", ErrBatchInnerNotSupported, operation)
	}
}

// shapeBatchInner shapes a built transaction as an XLS-56 inner: the inner-Batch flag joins
// whatever flags it already carries, the fee is zero because the outer Batch pays, and the
// signing key is present but empty because an inner is authorized by the Batch signature
// rather than by one of its own.
//
// The flag is set before flattening, which is what makes BaseTx.Flatten write the empty
// SigningPubKey; the zero Fee is written here, because a zero amount is otherwise omitted.
func shapeBatchInner(tx BatchInnerTransaction) transaction.FlatTransaction {
	flat := tx.Flatten()
	flags, _ := flat["Flags"].(uint32)
	flat["Flags"] = flags | types.TfInnerBatchTxn
	flat["Fee"] = "0"
	flat["SigningPubKey"] = ""
	return flat
}
