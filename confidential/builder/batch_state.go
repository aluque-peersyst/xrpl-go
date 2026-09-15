package builder

import (
	"fmt"
	"strings"

	"github.com/Peersyst/xrpl-go/confidential/elgamal"
	"github.com/Peersyst/xrpl-go/pkg/mptsizes"
	"github.com/Peersyst/xrpl-go/xrpl/transaction/types"
)

// This file holds the predicted-state machinery BuildBatch runs on. A confidential proof
// binds the balance and the version the transaction consumes, and the ledger cannot show
// what an earlier inner of the same Batch will leave behind, so the assembler predicts it:
// one initial read per MPToken from a single validated ledger, then a homomorphic
// transition per inner. Every prediction reproduces exactly what the transactor does to
// the ledger, so an inner built against a prediction verifies against the real state.

// tokenKey identifies one MPToken, which XLS-33 keys by holder and issuance. The holder is
// the decoded AccountID in its canonical classic spelling rather than the address the
// caller wrote, so the classic and X-address forms of one account resolve to the same
// state, and the issuance ID is upper-cased, because hex case carries no meaning on the
// wire.
type tokenKey struct {
	holder   string
	issuance string
}

// newTokenKey decodes an address and normalizes an issuance ID into a state map key.
func newTokenKey(holder, issuanceID string) (tokenKey, error) {
	decoded, err := decodeBuilderAddress(holder)
	if err != nil {
		return tokenKey{}, fmt.Errorf("%w: %w", ErrInvalidAddress, err)
	}
	return tokenKey{holder: decoded.Classic, issuance: strings.ToUpper(issuanceID)}, nil
}

// String renders the key for an error message.
func (k tokenKey) String() string {
	return fmt.Sprintf("%s on issuance %s", k.holder, k.issuance)
}

// predictedBalance is one confidential ciphertext field of an MPToken as the assembler
// believes it will stand when the inner being built applies. It has three states, and the
// difference between the last two is what keeps a doomed proof from being generated:
//
//   - known: the ciphertext is in hand, either as read from the ledger or as predicted.
//   - absent: the field is not on the MPToken at all, which is how rippled represents a
//     holder that has never converted. A transaction that needs it is rejected by the
//     ledger, so it is rejected here, naming the condition the transactor would.
//   - unpredictable: the field exists, or an earlier inner in this Batch brought it into
//     existence, but its value cannot be reproduced here. Every such value traces back to
//     the canonical encrypted zero, which the transactor derives from the holder key, the
//     account and the issuance: a merge resets the inbox to it, a clawback resets all four
//     balances to it, and a holder's first convert initializes its balances to it before
//     crediting them. An inner that needs only the field's existence still builds; one that
//     needs its value fails here rather than on the ledger.
type predictedBalance struct {
	value         string
	unpredictable bool
}

// knownBalance is a ciphertext read from the ledger or predicted from one.
func knownBalance(ciphertext string) predictedBalance {
	return predictedBalance{value: ciphertext}
}

// unpredictableBalance marks a field that exists but whose value this package cannot
// reproduce, because the transactor derived it from the canonical encrypted zero.
func unpredictableBalance() predictedBalance {
	return predictedBalance{unpredictable: true}
}

// exists reports whether the MPToken carries the field at all, which is all a transactor
// checks where it does not read the value.
func (b predictedBalance) exists() bool {
	return b.value != "" || b.unpredictable
}

// requireExists rejects a field the MPToken does not carry, for an inner that needs the
// field present but never reads it.
func (b predictedBalance) requireExists(field string, absent error) error {
	if !b.exists() {
		return fmt.Errorf("%w: %s is missing", absent, field)
	}
	return nil
}

// require reads a ciphertext an inner cannot be built without, naming which of the two
// unusable states it is in. absent reports the sentinel for a field the ledger never had,
// which differs per operation: a spender missing its own state is a different condition
// from a destination that never opted in.
func (b predictedBalance) require(field string, absent error) (string, error) {
	if b.unpredictable {
		return "", fmt.Errorf("%w: %s", ErrBatchUnpredictableState, field)
	}
	if b.value == "" {
		return "", fmt.Errorf("%w: %s is missing", absent, field)
	}
	return b.value, nil
}

// credit adds an incoming ciphertext. A field the MPToken does not carry yet is initialized
// to the credit itself: ConfidentialMPTConvert's first-time branch writes the transaction's
// own ciphertexts into the inbox and the mirrors rather than crediting a zero, so that is
// what the ledger ends up holding. A field whose value could not be followed stays that
// way, because the credit lands on a value this package does not have.
func (b predictedBalance) credit(field, amountCt string) (predictedBalance, error) {
	if b.unpredictable {
		return unpredictableBalance(), nil
	}
	if b.value == "" {
		return knownBalance(amountCt), nil
	}
	sum, err := elgamal.Add(b.value, amountCt)
	if err != nil {
		return predictedBalance{}, fmt.Errorf("%w: %s: %w", ErrCryptoFailed, field, err)
	}
	return knownBalance(sum), nil
}

// debit subtracts an outgoing ciphertext. The field must exist, because the transactor
// rejects a holder missing it; a value that cannot be followed stays unpredictable, since
// the subtraction still happens on the ledger.
func (b predictedBalance) debit(field, amountCt string, absent error) (predictedBalance, error) {
	if err := b.requireExists(field, absent); err != nil {
		return predictedBalance{}, err
	}
	if b.unpredictable {
		return unpredictableBalance(), nil
	}
	difference, err := elgamal.Subtract(b.value, amountCt)
	if err != nil {
		return predictedBalance{}, fmt.Errorf("%w: %s: %w", ErrCryptoFailed, field, err)
	}
	return knownBalance(difference), nil
}

// tokenState is the confidential state of one MPToken as the next inner will find it.
type tokenState struct {
	// holderKey is the holder's registered ElGamal key, empty until a convert registers
	// one. An in-batch convert records it here so a later send to this holder can encrypt
	// to a key the ledger does not carry yet.
	holderKey string
	// spending is ConfidentialBalanceSpending, the only balance a send or a convert-back
	// may debit.
	spending predictedBalance
	// inbox is ConfidentialBalanceInbox, where a convert and an incoming send land until a
	// merge moves them across.
	inbox predictedBalance
	// issuerEnc and auditorEnc are the mirror balances the transactor keeps in step with
	// the holder's own, encrypted to the issuer and to the auditor. A clawback proves
	// against the issuer mirror, so the assembler tracks it as closely as the balance.
	issuerEnc  predictedBalance
	auditorEnc predictedBalance
	// version is ConfidentialBalanceVersion, which every send and convert-back proof binds
	// and which each spend, merge, and clawback increments. XLS-96 9.3 wraps it at 32 bits,
	// which is what bump relies on.
	version uint32
	// publicAmount is MPTAmount, the public balance a convert debits and a convert-back
	// credits. It is tracked so repeated converts in one Batch are funded against what the
	// earlier ones leave rather than against the pre-batch balance.
	publicAmount uint64
}

// bump advances the balance version the way the transactor does, wrapping at 32 bits.
func (s tokenState) bump() tokenState {
	s.version++
	return s
}

// batchState is the whole predicted state of one assembly: every MPToken the Batch reads or
// writes, plus the per-issuance facts the inners share.
type batchState struct {
	tokens    map[tokenKey]*tokenState
	issuances map[string]*batchIssuance
}

// batchIssuance holds one issuance's shared state. The capability flags and keys come from
// the validated ledger and never change within a Batch, because the assembler refuses a
// plain inner that could change them. The outstanding amount does change, so it is tracked.
type batchIssuance struct {
	issuanceState
	// outstanding is ConfidentialOutstandingAmount as the next inner will find it. It is
	// the ceiling on any single holder's confidential balance, so it bounds every
	// decryption search the assembler runs, and a convert-back above it fails on the
	// ledger. A convert raises it, a convert-back and a clawback lower it.
	outstanding uint64
}

// token returns the predicted state of one MPToken. Every key referenced by an operation is
// loaded before the build loop starts, so a missing one is an assembler bug rather than a
// condition a caller can reach.
func (s *batchState) token(key tokenKey) (*tokenState, error) {
	state, ok := s.tokens[key]
	if !ok {
		return nil, fmt.Errorf("%w: no state loaded for %s", ErrInvalidLedgerState, key)
	}
	return state, nil
}

// issuance returns one issuance's shared state, by the same contract as token.
func (s *batchState) issuance(issuanceID string) (*batchIssuance, error) {
	state, ok := s.issuances[strings.ToUpper(issuanceID)]
	if !ok {
		return nil, fmt.Errorf("%w: no state loaded for issuance %s", ErrInvalidLedgerState, issuanceID)
	}
	return state, nil
}

// creditOutstanding raises the confidential supply by a converted amount, saturating at the
// protocol cap. The cap is the ceiling the ledger itself enforces, and the value is only
// ever used as a decryption bound and a convert-back ceiling, so saturating keeps both
// meaningful where an unchecked sum would wrap.
func (i *batchIssuance) creditOutstanding(amount uint64) {
	maximum := uint64(types.MaxMPTAmount)
	if i.outstanding > maximum-amount {
		i.outstanding = maximum
		return
	}
	i.outstanding += amount
}

// debitOutstanding lowers the confidential supply by an amount leaving it. Every caller
// checks the amount against the outstanding total first, so the floor is never reached in
// practice and exists so a future caller cannot wrap it.
func (i *batchIssuance) debitOutstanding(amount uint64) {
	if amount > i.outstanding {
		i.outstanding = 0
		return
	}
	i.outstanding -= amount
}

// searchRange narrows a caller's decryption bounds to the confidential supply as the
// assembler predicts it at this point in the Batch. The standalone builders bound the
// search by the supply the ledger reports, which is the pre-batch figure; inside a Batch an
// earlier convert can raise a balance above it, so the running total is used instead.
func (i *batchIssuance) searchRange(bounds elgamal.AmountRange) (elgamal.AmountRange, error) {
	return boundedBalanceRange(bounds, i.outstanding)
}

// mirrorCiphertexts pairs an operation's issuer and auditor ciphertexts for a transition
// that applies the same change to both mirror balances.
type mirrorCiphertexts struct {
	issuer  string
	auditor string
}

// applySpend applies what ConfidentialMPTSend and ConfidentialMPTConvertBack do to the
// spender's own MPToken: the transaction's ciphertexts come off the spending balance and
// off each mirror balance, and the version advances so the next proof binds the new one.
func (s *tokenState) applySpend(spendCt string, mirrors mirrorCiphertexts) error {
	spending, err := s.spending.debit("ConfidentialBalanceSpending", spendCt, ErrMissingSenderState)
	if err != nil {
		return err
	}
	issuerEnc, err := s.issuerEnc.debit("IssuerEncryptedBalance", mirrors.issuer, ErrMissingSenderState)
	if err != nil {
		return err
	}
	auditorEnc := s.auditorEnc
	if mirrors.auditor != "" {
		if auditorEnc, err = s.auditorEnc.debit("AuditorEncryptedBalance", mirrors.auditor, ErrMissingSenderState); err != nil {
			return err
		}
	}

	s.spending, s.issuerEnc, s.auditorEnc = spending, issuerEnc, auditorEnc
	*s = s.bump()
	return nil
}

// applyConvertCredit applies what ConfidentialMPTConvert does to the converting holder: the
// transaction's ciphertexts are added to the inbox and to each mirror balance, and a
// holder's first convert brings all of those fields, and the spending balance, into
// existence first. The version is untouched, because a convert lands in the inbox and only
// a merge moves it across, which is also why the spending balance takes no credit.
func (s *tokenState) applyConvertCredit(holderCt string, mirrors mirrorCiphertexts, firstTime bool) error {
	inbox, err := s.inbox.credit("ConfidentialBalanceInbox", holderCt)
	if err != nil {
		return err
	}
	issuerEnc, err := s.issuerEnc.credit("IssuerEncryptedBalance", mirrors.issuer)
	if err != nil {
		return err
	}
	auditorEnc := s.auditorEnc
	if mirrors.auditor != "" {
		if auditorEnc, err = s.auditorEnc.credit("AuditorEncryptedBalance", mirrors.auditor); err != nil {
			return err
		}
	}

	s.inbox, s.issuerEnc, s.auditorEnc = inbox, issuerEnc, auditorEnc
	// A first-time convert also initializes the spending balance, and that one field is
	// the canonical encrypted zero rather than a transaction ciphertext: the transactor
	// derives it from the holder key, the account and the issuance. It is recorded as
	// existing and unreadable, so a merge after it still builds while a spend does not.
	if firstTime && !s.spending.exists() {
		s.spending = unpredictableBalance()
	}
	return nil
}

// applyInboxCredit applies what ConfidentialMPTSend does to the destination: the inbox and
// each mirror balance take the matching ciphertext, re-randomized under the key that
// ciphertext belongs to. The destination's version is left alone, because the transactor
// advances only the spender's.
//
// Re-randomization is the part a client must reproduce exactly. The transactor re-blinds
// each credited ciphertext by adding an encryption of zero under the target key, using the
// proof's own challenge as the blinding factor, so that the value credited on the ledger is
// not byte-identical to the one on the wire. Predicting the credit without it yields a
// ciphertext that decrypts to the right amount but is not the one the ledger holds, and the
// next proof built against it fails.
func (s *tokenState) applyInboxCredit(credit inboxCredit) error {
	destinationKey, err := s.requireHolderKey()
	if err != nil {
		return err
	}
	inboxCt, err := rerandomize(credit.destinationCt, destinationKey, credit.challenge)
	if err != nil {
		return err
	}
	inbox, err := s.inbox.credit("ConfidentialBalanceInbox", inboxCt)
	if err != nil {
		return err
	}

	issuerCt, err := rerandomize(credit.mirrors.issuer, credit.issuerKey, credit.challenge)
	if err != nil {
		return err
	}
	issuerEnc, err := s.issuerEnc.credit("IssuerEncryptedBalance", issuerCt)
	if err != nil {
		return err
	}

	auditorEnc := s.auditorEnc
	if credit.mirrors.auditor != "" {
		auditorCt, err := rerandomize(credit.mirrors.auditor, credit.auditorKey, credit.challenge)
		if err != nil {
			return err
		}
		if auditorEnc, err = s.auditorEnc.credit("AuditorEncryptedBalance", auditorCt); err != nil {
			return err
		}
	}

	s.inbox, s.issuerEnc, s.auditorEnc = inbox, issuerEnc, auditorEnc
	return nil
}

// applyMerge applies what ConfidentialMPTMergeInbox does: the inbox is folded into the
// spending balance and reset to the canonical encrypted zero, and the version advances.
// The reset is the one effect this package cannot reproduce, so the inbox becomes
// unpredictable and any later inner that reads it is rejected.
func (s *tokenState) applyMerge() error {
	spending := unpredictableBalance()
	// Both sides have to be known for the sum to be: an inbox the assembler cannot read
	// leaves a spending balance it cannot read either.
	if s.spending.value != "" && s.inbox.value != "" {
		merged, err := elgamal.Add(s.spending.value, s.inbox.value)
		if err != nil {
			return fmt.Errorf("%w: ConfidentialBalanceSpending: %w", ErrCryptoFailed, err)
		}
		spending = knownBalance(merged)
	}

	s.spending, s.inbox = spending, unpredictableBalance()
	*s = s.bump()
	return nil
}

// applyClawback applies what ConfidentialMPTClawback does: every confidential balance of
// the holder is reset to the canonical encrypted zero and the version advances. None of
// the four resets can be reproduced here, so all become unpredictable.
func (s *tokenState) applyClawback() {
	s.spending = unpredictableBalance()
	s.inbox = unpredictableBalance()
	s.issuerEnc = unpredictableBalance()
	s.auditorEnc = unpredictableBalance()
	*s = s.bump()
}

// requireHolderKey reads the holder's registered encryption key, which a send's destination
// must have before anything can be encrypted to it.
func (s *tokenState) requireHolderKey() (string, error) {
	if s.holderKey == "" {
		return "", fmt.Errorf("%w: HolderEncryptionKey is missing", ErrReceiverNotOptedIn)
	}
	return s.holderKey, nil
}

// inboxCredit carries everything applyInboxCredit needs from a built send.
type inboxCredit struct {
	// challenge is the re-randomization scalar, which is the leading half of the send
	// proof. The transactor takes it from the same place.
	challenge string
	// destinationCt is DestinationEncryptedAmount, the amount under the destination's key.
	destinationCt string
	// mirrors are the issuer and auditor ciphertexts of the same amount.
	mirrors mirrorCiphertexts
	// issuerKey and auditorKey are the issuance keys the mirrors are encrypted under, which
	// is what each mirror's re-randomization must use.
	issuerKey  string
	auditorKey string
}

// rerandomize reproduces the transactor's re-blinding of a credited ciphertext: an
// encryption of zero under the target key, with the send proof's challenge as the blinding
// factor, added to the ciphertext.
func rerandomize(ciphertext, pubKey, challenge string) (string, error) {
	zero, err := elgamal.Encrypt(0, pubKey, challenge)
	if err != nil {
		return "", fmt.Errorf("%w: re-randomizing a credited ciphertext: %w", ErrCryptoFailed, err)
	}
	blinded, err := elgamal.Add(ciphertext, zero)
	if err != nil {
		return "", fmt.Errorf("%w: re-randomizing a credited ciphertext: %w", ErrCryptoFailed, err)
	}
	return blinded, nil
}

// sendChallenge extracts the re-randomization scalar from a send proof, which is its
// leading blinding-factor-sized half.
func sendChallenge(zkProof string) (string, error) {
	const challengeHexLength = 2 * mptsizes.BlindingFactorSize
	if len(zkProof) < challengeHexLength {
		return "", fmt.Errorf("%w: send proof is shorter than its challenge", ErrCryptoFailed)
	}
	return zkProof[:challengeHexLength], nil
}

// readBatchTokenState reads one MPToken's confidential state from the validated snapshot.
// Every field is optional, because the same read serves a holder that has never converted
// and one holding a full confidential balance; the operations that need a given field
// require it where they use it, with the sentinel that names their own role.
//
// usable runs the locked and authorized checks the transactors make before they look at any
// confidential state. It is skipped for an MPToken only a clawback touches, because the
// clawback transactor deliberately runs neither: an issuer must be able to claw back from a
// holder it has locked.
func readBatchTokenState(snapshot *ledgerSnapshot, issuance issuanceState, key tokenKey, holder string, usable bool) (*tokenState, error) {
	resp, err := getMPTokenEntry(snapshot, key.issuance, holder)
	if err != nil {
		return nil, err
	}
	if usable {
		if err := requireHolderUsable(resp.Node, issuance); err != nil {
			return nil, err
		}
	}

	state := &tokenState{}
	if state.holderKey, err = optionalString(resp.Node, "HolderEncryptionKey"); err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name   string
		target *predictedBalance
	}{
		{"ConfidentialBalanceSpending", &state.spending},
		{"ConfidentialBalanceInbox", &state.inbox},
		{"IssuerEncryptedBalance", &state.issuerEnc},
		{"AuditorEncryptedBalance", &state.auditorEnc},
	} {
		ciphertext, err := optionalString(resp.Node, field.name)
		if err != nil {
			return nil, err
		}
		*field.target = knownBalance(ciphertext)
	}
	// An MPToken carrying no version is at version 0, which XLS-96 7.5.5 makes the starting
	// value, so only a present but unreadable field is malformed.
	if state.version, err = optionalUint32(resp.Node, "ConfidentialBalanceVersion"); err != nil {
		return nil, err
	}
	if state.publicAmount, err = optionalUint64(resp.Node, "MPTAmount"); err != nil {
		return nil, err
	}
	// Every prediction in a Batch is anchored to this reading, so the whole chain is stale
	// if a transaction of this holder's is already in flight. The standalone builders make
	// this check only where a proof binds the version; here it covers every MPToken loaded,
	// because an inner whose proof binds no version can still leave state a later inner's
	// proof does bind.
	if err := requireCurrentBalanceVersion(snapshot, resp.Index, state.version); err != nil {
		return nil, err
	}
	return state, nil
}
