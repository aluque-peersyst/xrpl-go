package builder

import (
	"fmt"

	"github.com/Peersyst/xrpl-go/confidential/elgamal"
	"github.com/Peersyst/xrpl-go/xrpl/transaction"
	"github.com/Peersyst/xrpl-go/xrpl/transaction/types"
)

// This file holds one function per confidential operation. Each is the batch counterpart of
// a Build* helper: it makes the same validations and preflight decisions, but reads the
// predicted state instead of the ledger, hands the result to the same Prepare* helper, and
// then advances the predictions by what the built transaction does.

// prepareBatchConvert builds a ConfidentialMPTConvert inner. It is the batch counterpart of
// BuildConvert, and differs in the two places the ledger cannot answer inside a Batch: the
// public balance it is funded from is the one earlier inners leave, and the key registration
// is decided from the predicted holder key, so two converts by one holder in a Batch do not
// both try to register it.
func prepareBatchConvert(state *batchState, op ConvertOp, options TxOptions) (BatchInnerTransaction, error) {
	params := op.BuildConvertParams
	if err := validateConvertBase(params); err != nil {
		return nil, err
	}
	issuance, token, err := state.resolve(op.Account, op.IssuanceID)
	if err != nil {
		return nil, err
	}
	// A convert moves public MPT the holder must already hold, and the transactor rejects
	// one it cannot fund with tecINSUFFICIENT_FUNDS. A zero-amount convert funds nothing,
	// which is what makes it the opt-in path for a holder with no balance yet.
	if op.Amount > token.publicAmount {
		return nil, ErrInsufficientBalance
	}

	firstTime := token.holderKey == ""
	if !firstTime && !sameEncryptionKey(token.holderKey, op.HolderPubKey) {
		return nil, fmt.Errorf("%w: holder key", ErrKeyMismatch)
	}

	params.TxOptions = options
	tx, err := PrepareConvert(ConvertParams{
		BuildConvertParams: params,
		IssuerPubKey:       issuance.issuerKey,
		AuditorPubKey:      issuance.auditorKey,
		FirstTime:          firstTime,
	})
	if err != nil {
		return nil, err
	}

	if err := token.applyConvertCredit(tx.HolderEncryptedAmount, mirrorsOf(tx.IssuerEncryptedAmount, tx.AuditorEncryptedAmount), firstTime); err != nil {
		return nil, err
	}
	// The convert publishes the holder's key whether or not this transaction registers it,
	// so a later send to this holder can encrypt to it before the ledger carries it.
	token.holderKey = op.HolderPubKey
	token.publicAmount -= op.Amount
	issuance.creditOutstanding(op.Amount)
	return tx, nil
}

// prepareBatchConvertBack builds a ConfidentialMPTConvertBack inner. It is the batch
// counterpart of BuildConvertBack: the spending balance it debits and the version its proof
// binds come from the predictions, and the confidential supply it is checked against is the
// running one, so a convert earlier in the same Batch funds it.
func prepareBatchConvertBack(state *batchState, op ConvertBackOp, options TxOptions) (BatchInnerTransaction, error) {
	params := op.BuildConvertBackParams
	if err := validateConvertBackBase(params); err != nil {
		return nil, err
	}
	if err := op.BalanceRange.Validate(); err != nil {
		return nil, err
	}
	issuance, token, err := state.resolve(op.Account, op.IssuanceID)
	if err != nil {
		return nil, err
	}
	if op.Amount > issuance.outstanding {
		return nil, ErrAmountExceedsOutstanding
	}

	spendingCt, err := requireSpendable(token, issuance, op.HolderPubKey)
	if err != nil {
		return nil, err
	}
	currentBalance, err := decryptPredictedBalance(issuance, spendingCt, op.HolderPrivKey, op.BalanceRange, "spending balance")
	if err != nil {
		return nil, err
	}

	params.TxOptions = options
	tx, err := PrepareConvertBack(ConvertBackParams{
		BuildConvertBackParams: params,
		IssuerPubKey:           issuance.issuerKey,
		AuditorPubKey:          issuance.auditorKey,
		BalanceVersion:         token.version,
		CurrentBalance:         currentBalance,
		CurrentBalanceCt:       spendingCt,
	})
	if err != nil {
		return nil, err
	}

	if err := token.applySpend(tx.HolderEncryptedAmount, mirrorsOf(tx.IssuerEncryptedAmount, tx.AuditorEncryptedAmount)); err != nil {
		return nil, err
	}
	token.creditPublic(op.Amount)
	issuance.debitOutstanding(op.Amount)
	return tx, nil
}

// prepareBatchSend builds a ConfidentialMPTSend inner. It is the batch counterpart of
// BuildSend, and is the operation that changes two MPTokens: the sender's balances fall by
// the transferred amount, and the destination's inbox and mirrors take the same amount
// re-randomized the way the transactor re-randomizes it.
func prepareBatchSend(state *batchState, op SendOp, options TxOptions) (BatchInnerTransaction, error) {
	params := op.BuildSendParams
	if err := validateSendBase(params); err != nil {
		return nil, err
	}
	if err := op.BalanceRange.Validate(); err != nil {
		return nil, err
	}
	issuance, sender, err := state.resolve(op.Account, op.IssuanceID)
	if err != nil {
		return nil, err
	}
	if !issuance.canTransfer() {
		return nil, ErrTransferDisabled
	}
	if issuance.transferFee > 0 {
		return nil, ErrTransferFeeSet
	}

	spendingCt, err := requireSpendable(sender, issuance, op.SenderPubKey)
	if err != nil {
		return nil, err
	}
	currentBalance, err := decryptPredictedBalance(issuance, spendingCt, op.SenderPrivKey, op.BalanceRange, "spending balance")
	if err != nil {
		return nil, err
	}

	destination, err := state.tokenFor(op.Destination, op.IssuanceID)
	if err != nil {
		return nil, err
	}
	destinationKey, err := requireReceivable(destination, issuance)
	if err != nil {
		return nil, err
	}

	params.TxOptions = options
	tx, err := PrepareSend(SendParams{
		BuildSendParams:  params,
		ReceiverPubKey:   destinationKey,
		IssuerPubKey:     issuance.issuerKey,
		AuditorPubKey:    issuance.auditorKey,
		BalanceVersion:   sender.version,
		CurrentBalance:   currentBalance,
		CurrentBalanceCt: spendingCt,
	})
	if err != nil {
		return nil, err
	}

	mirrors := mirrorsOf(tx.IssuerEncryptedAmount, tx.AuditorEncryptedAmount)
	if err := sender.applySpend(tx.SenderEncryptedAmount, mirrors); err != nil {
		return nil, err
	}
	challenge, err := sendChallenge(tx.ZKProof)
	if err != nil {
		return nil, err
	}
	if err := destination.applyInboxCredit(inboxCredit{
		challenge:     challenge,
		destinationCt: tx.DestinationEncryptedAmount,
		mirrors:       mirrors,
		issuerKey:     issuance.issuerKey,
		auditorKey:    issuance.auditorKey,
	}); err != nil {
		return nil, err
	}
	return tx, nil
}

// prepareBatchMergeInbox builds a ConfidentialMPTMergeInbox inner. It is the batch
// counterpart of BuildMergeInbox. The merge carries no proof, so nothing about it binds the
// predictions, but it resets the inbox to a value this package cannot reproduce, which is
// why any later inner reading that inbox is refused.
func prepareBatchMergeInbox(state *batchState, op MergeInboxOp, options TxOptions) (BatchInnerTransaction, error) {
	params := op.BuildMergeInboxParams
	if err := validateMergeInboxBase(params); err != nil {
		return nil, err
	}
	_, token, err := state.resolve(op.Account, op.IssuanceID)
	if err != nil {
		return nil, err
	}
	// The transactor rejects a holder missing either balance or the holder key with
	// tecNO_PERMISSION, and requires nothing else of the MPToken. Only the presence of the
	// balances is checked, not their values: a merge carries no proof, so a balance this
	// package cannot read still merges, and it is the next inner to read the result that
	// is refused.
	if _, err := token.requireHolderKey(); err != nil {
		return nil, fmt.Errorf("%w: HolderEncryptionKey is missing", ErrMissingSenderState)
	}
	if err := token.spending.requireExists("ConfidentialBalanceSpending", ErrMissingSenderState); err != nil {
		return nil, err
	}
	if err := token.inbox.requireExists("ConfidentialBalanceInbox", ErrMissingSenderState); err != nil {
		return nil, err
	}

	params.TxOptions = options
	tx, err := PrepareMergeInbox(MergeInboxParams{BuildMergeInboxParams: params})
	if err != nil {
		return nil, err
	}
	if err := token.applyMerge(); err != nil {
		return nil, err
	}
	return tx, nil
}

// prepareBatchClawback builds a ConfidentialMPTClawback inner. It is the batch counterpart
// of BuildClawback: the amount is the holder's whole confidential balance as the earlier
// inners leave it, decrypted from the predicted issuer mirror rather than from the ledger.
func prepareBatchClawback(state *batchState, op ClawbackOp, options TxOptions) (BatchInnerTransaction, error) {
	params := op.BuildClawbackParams
	if err := validateClawbackBase(params); err != nil {
		return nil, err
	}
	if err := op.BalanceRange.Validate(); err != nil {
		return nil, err
	}
	issuance, err := state.issuance(op.IssuanceID)
	if err != nil {
		return nil, err
	}
	if !issuance.canClawback() {
		return nil, ErrClawbackDisabled
	}
	holder, err := state.tokenFor(op.Holder, op.IssuanceID)
	if err != nil {
		return nil, err
	}

	// Both fields are ordinary holder state rather than a malformed entry: a holder that
	// never opted into confidential balances simply has neither.
	if _, err := holder.requireHolderKey(); err != nil {
		return nil, fmt.Errorf("%w: HolderEncryptionKey is missing", ErrMissingSenderState)
	}
	issuerCt, err := holder.issuerEnc.require("IssuerEncryptedBalance", ErrMissingSenderState)
	if err != nil {
		return nil, err
	}
	amount, err := decryptPredictedBalance(issuance, issuerCt, op.IssuerPrivKey, op.BalanceRange, "holder balance")
	if err != nil {
		return nil, err
	}

	params.TxOptions = options
	tx, err := PrepareClawback(ClawbackParams{
		BuildClawbackParams: params,
		Amount:              amount,
		IssuerPubKey:        issuance.issuerKey,
		IssuerCiphertext:    issuerCt,
	})
	if err != nil {
		return nil, err
	}

	holder.applyClawback()
	issuance.debitOutstanding(amount)
	return tx, nil
}

// resolve looks up the issuance and the submitter's own MPToken in one step, which is what
// every operation but the clawback needs.
func (s *batchState) resolve(account, issuanceID string) (*batchIssuance, *tokenState, error) {
	issuance, err := s.issuance(issuanceID)
	if err != nil {
		return nil, nil, err
	}
	token, err := s.tokenFor(account, issuanceID)
	if err != nil {
		return nil, nil, err
	}
	return issuance, token, nil
}

// tokenFor looks up one MPToken by the address and issuance an operation names.
func (s *batchState) tokenFor(holder, issuanceID string) (*tokenState, error) {
	key, err := newTokenKey(holder, issuanceID)
	if err != nil {
		return nil, err
	}
	return s.token(key)
}

// creditPublic returns public MPT to a holder, saturating at the protocol cap. A
// convert-back can only return what a convert took, so the cap is unreachable in practice
// and is here so the tracked amount cannot wrap.
func (s *tokenState) creditPublic(amount uint64) {
	maximum := uint64(types.MaxMPTAmount)
	if s.publicAmount > maximum-amount {
		s.publicAmount = maximum
		return
	}
	s.publicAmount += amount
}

// requireSpendable checks the state ConfidentialMPTSend and ConfidentialMPTConvertBack both
// demand of the spender, in the order their transactors do, and returns the spending
// ciphertext the proof consumes. The mirror balances are required although the proof does
// not read them, because the transactor debits each one and rejects a holder missing any.
func requireSpendable(token *tokenState, issuance *batchIssuance, pubKey string) (string, error) {
	if token.holderKey == "" {
		return "", fmt.Errorf("%w: HolderEncryptionKey is missing", ErrMissingSenderState)
	}
	if !sameEncryptionKey(token.holderKey, pubKey) {
		return "", fmt.Errorf("%w: holder key", ErrKeyMismatch)
	}
	// The proof binds the spending ciphertext, so that one is needed by value. The mirrors
	// are only required to exist, which is what the transactor checks: it debits them
	// homomorphically without reading them, so a mirror this package cannot follow does not
	// stop the send, it only stops a later inner that needs the result.
	spending, err := token.spending.require("ConfidentialBalanceSpending", ErrMissingSenderState)
	if err != nil {
		return "", err
	}
	if err := token.issuerEnc.requireExists("IssuerEncryptedBalance", ErrMissingSenderState); err != nil {
		return "", err
	}
	if issuance.hasAuditor() {
		if err := token.auditorEnc.requireExists("AuditorEncryptedBalance", ErrMissingSenderState); err != nil {
			return "", err
		}
	}
	return spending, nil
}

// requireReceivable checks the state a confidential send's destination must already have and
// returns the key the transferred amount is encrypted under. The transactor credits the
// inbox and each mirror balance, so all of them must exist before the send, whether they
// were on the ledger or an earlier convert in this Batch created them.
func requireReceivable(token *tokenState, issuance *batchIssuance) (string, error) {
	holderKey, err := token.requireHolderKey()
	if err != nil {
		return "", err
	}
	// The transactor checks that each credited field is present, not what it holds, so
	// presence is all that is required here too.
	for _, field := range []struct {
		name    string
		balance predictedBalance
	}{
		{"ConfidentialBalanceInbox", token.inbox},
		{"IssuerEncryptedBalance", token.issuerEnc},
	} {
		if err := field.balance.requireExists(field.name, ErrReceiverNotOptedIn); err != nil {
			return "", err
		}
	}
	if issuance.hasAuditor() {
		if err := token.auditorEnc.requireExists("AuditorEncryptedBalance", ErrReceiverNotOptedIn); err != nil {
			return "", err
		}
	}
	return holderKey, nil
}

// decryptPredictedBalance recovers the plaintext a proof needs from a predicted ciphertext,
// under the caller's bounds narrowed to the confidential supply as it stands at this point
// in the Batch. Narrowing against the running supply rather than the figure on the ledger is
// what keeps a balance an earlier convert topped up inside the search.
func decryptPredictedBalance(
	issuance *batchIssuance,
	ciphertext, privKey string,
	bounds elgamal.AmountRange,
	what string,
) (uint64, error) {
	searchRange, err := issuance.searchRange(bounds)
	if err != nil {
		return 0, err
	}
	amount, err := elgamal.Decrypt(ciphertext, privKey, searchRange)
	if err != nil {
		return 0, fmt.Errorf("%w: failed to decrypt %s: %w", ErrCryptoFailed, what, err)
	}
	return amount, nil
}

// mirrorsOf pairs the issuer ciphertext a confidential transaction always carries with the
// auditor ciphertext it carries only under an auditing issuance.
func mirrorsOf(issuerCt string, auditorCt *string) mirrorCiphertexts {
	mirrors := mirrorCiphertexts{issuer: issuerCt}
	if auditorCt != nil {
		mirrors.auditor = *auditorCt
	}
	return mirrors
}

// supportedInnerTransactionTypes is the set of ordinary transaction types the assembler
// accepts as a ready-made inner. Membership turns on one question: can the transaction
// change something a later inner's proof depends on? Every type here touches neither
// confidential balances, nor an MPToken's existence or authorization, nor an issuance, so
// the predictions hold across it.
//
// The types kept out are kept out deliberately. MPTokenAuthorize creates and deletes the
// MPToken the predictions are keyed by, MPTokenIssuanceSet can lock an issuance or change
// its keys, Payment and Clawback can move public MPT that a convert is funded from, and the
// confidential types themselves belong in the operation list where the assembler can build
// them against the chain. Each of those belongs in its own transaction before or after the
// Batch.
var supportedInnerTransactionTypes = map[transaction.TxType]struct{}{
	transaction.AccountSetTx:       {},
	transaction.SetRegularKeyTx:    {},
	transaction.SignerListSetTx:    {},
	transaction.TicketCreateTx:     {},
	transaction.TrustSetTx:         {},
	transaction.DepositPreauthTx:   {},
	transaction.DelegateSetTx:      {},
	transaction.CredentialCreateTx: {},
	transaction.CredentialAcceptTx: {},
	transaction.CredentialDeleteTx: {},
}

// IsSupportedInnerTransactionType reports whether BuildBatch accepts a ready-made
// transaction of this type as a TransactionOp inner. Anything else must be submitted
// outside the Batch, because the assembler cannot predict what it leaves behind.
func IsSupportedInnerTransactionType(txType transaction.TxType) bool {
	_, supported := supportedInnerTransactionTypes[txType]
	return supported
}

// validatePlainInner rejects a ready-made inner the assembler cannot carry: an unsupported
// type, a transaction its own validation refuses, and the fields XLS-56 forbids on an inner.
func validatePlainInner(op TransactionOp) error {
	if op.Tx == nil {
		return ErrBatchMissingOperation
	}
	txType := op.Tx.TxType()
	if !IsSupportedInnerTransactionType(txType) {
		return fmt.Errorf("%w: %s", ErrBatchInnerNotSupported, txType)
	}
	if err := validatePreparedTransaction(op.Tx); err != nil {
		return err
	}

	flat := op.Tx.Flatten()
	if _, ok := flat["Account"].(string); !ok {
		return ErrMissingAccount
	}
	// An inner is authorized by the Batch signature, and expires with the Batch rather than
	// on a deadline of its own, so each of these fields makes the whole Batch invalid.
	for _, field := range []string{"LastLedgerSequence", "TxnSignature", "Signers"} {
		if _, present := flat[field]; present {
			return fmt.Errorf("%w: %s is not allowed on a Batch inner", ErrBatchInnerNotSupported, field)
		}
	}
	return nil
}

// plainInnerAccount reports the account a ready-made inner's nonce comes from.
func plainInnerAccount(op TransactionOp) (string, error) {
	if op.Tx == nil {
		return "", ErrBatchMissingOperation
	}
	account, ok := op.Tx.Flatten()["Account"].(string)
	if !ok {
		return "", ErrMissingAccount
	}
	return account, nil
}

// buildPlainInner shapes a ready-made transaction as a Batch inner, assigning it a
// position-derived sequence only when it carries neither nonce of its own. A caller that
// already chose a Sequence or a Ticket is passed through untouched, which mirrors how
// client autofill sequences a Batch.
func buildPlainInner(nonces *batchNonces, op TransactionOp) (transaction.FlatTransaction, error) {
	flat := op.Tx.Flatten()
	if !plainInnerHasNonce(flat) {
		account, err := plainInnerAccount(op)
		if err != nil {
			return nil, err
		}
		sequence, err := nonces.allocate(account, TxOptions{})
		if err != nil {
			return nil, err
		}
		flat["Sequence"] = sequence
	}

	flags, _ := flat["Flags"].(uint32)
	flat["Flags"] = flags | types.TfInnerBatchTxn
	flat["Fee"] = "0"
	flat["SigningPubKey"] = ""
	return flat, nil
}

// plainInnerHasNonce reports whether a flattened transaction already carries a nonce. A
// ticketed transaction also carries a zero Sequence, which the protocol requires, so the
// ticket is checked first and a zero Sequence alone does not count as one.
func plainInnerHasNonce(flat transaction.FlatTransaction) bool {
	if ticket, ok := flat["TicketSequence"].(uint32); ok && ticket != 0 {
		return true
	}
	sequence, ok := flat["Sequence"].(uint32)
	return ok && sequence != 0
}
