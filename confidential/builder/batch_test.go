package builder

import (
	"strconv"
	"testing"

	"github.com/Peersyst/xrpl-go/confidential/elgamal"
	xrplhash "github.com/Peersyst/xrpl-go/xrpl/hash"
	ledgerentries "github.com/Peersyst/xrpl-go/xrpl/ledger-entry-types"
	"github.com/Peersyst/xrpl-go/xrpl/queries/common"
	"github.com/Peersyst/xrpl-go/xrpl/transaction"
	"github.com/Peersyst/xrpl-go/xrpl/transaction/types"
	"github.com/stretchr/testify/require"
)

// sendOp builds a SendOp with the fixture's key for the sender and the standard bounds.
func sendOp(f *batchFixture, from, to, issuanceID string, amount uint64) SendOp {
	key := f.holderKey(from, issuanceID)
	return SendOp{BuildSendParams{
		Account:       from,
		Destination:   to,
		IssuanceID:    issuanceID,
		Amount:        amount,
		SenderPrivKey: key.PrivKeyHex,
		SenderPubKey:  key.PubKeyHex,
		BalanceRange:  batchRange(),
	}}
}

// convertOp builds a ConvertOp with the fixture's key for the holder.
func convertOp(f *batchFixture, holder, issuanceID string, amount uint64) ConvertOp {
	key := f.holderKey(holder, issuanceID)
	return ConvertOp{BuildConvertParams{
		Account:       holder,
		IssuanceID:    issuanceID,
		Amount:        amount,
		HolderPrivKey: key.PrivKeyHex,
		HolderPubKey:  key.PubKeyHex,
	}}
}

// convertBackOp builds a ConvertBackOp with the fixture's key for the holder.
func convertBackOp(f *batchFixture, holder, issuanceID string, amount uint64) ConvertBackOp {
	key := f.holderKey(holder, issuanceID)
	return ConvertBackOp{BuildConvertBackParams{
		Account:       holder,
		IssuanceID:    issuanceID,
		Amount:        amount,
		HolderPrivKey: key.PrivKeyHex,
		HolderPubKey:  key.PubKeyHex,
		BalanceRange:  batchRange(),
	}}
}

// mergeOp builds a MergeInboxOp for one holder.
func mergeOp(holder, issuanceID string) MergeInboxOp {
	return MergeInboxOp{BuildMergeInboxParams{Account: holder, IssuanceID: issuanceID}}
}

// clawbackOp builds a ClawbackOp submitted by the issuance's issuer.
func clawbackOp(f *batchFixture, issuer, holder, issuanceID string) ClawbackOp {
	return ClawbackOp{BuildClawbackParams{
		Account:       issuer,
		Holder:        holder,
		IssuanceID:    issuanceID,
		IssuerPrivKey: f.issuerKey(issuanceID).PrivKeyHex,
		BalanceRange:  batchRange(),
	}}
}

// TestBuildBatchRepeatedSpends pins the chain the assembler exists for: two sends from one
// account on one issuance. The second proof must bind the balance the first send leaves and
// the version it bumps, neither of which the ledger shows.
func TestBuildBatchRepeatedSpends(t *testing.T) {
	const (
		initialBalance = 500
		firstAmount    = 120
		secondAmount   = 80
		startSequence  = 7
		startVersion   = 3
	)

	fixture := newBatchFixture(t).
		withIssuance(testIssuanceID).
		withHolder(testAccount, testIssuanceID, holderFixture{spending: amountOf(initialBalance), version: startVersion}).
		withHolder(testDestination, testIssuanceID, holderFixture{inbox: amountOf(0)}).
		withSequence(testAccount, startSequence)

	senderKey := fixture.holderKey(testAccount, testIssuanceID)
	receiverKey := fixture.holderKey(testDestination, testIssuanceID)
	issuerKey := fixture.issuerKey(testIssuanceID)

	batch, err := BuildBatch(fixture.querier(), BuildBatchParams{
		Account: testAccount,
		Operations: []BatchOperation{
			sendOp(fixture, testAccount, testDestination, testIssuanceID, firstAmount),
			sendOp(fixture, testAccount, testDestination, testIssuanceID, secondAmount),
		},
	})
	require.NoError(t, err)

	require.Equal(t, uint32(startSequence), batch.Sequence, "the outer Batch spends the account's current sequence")
	require.Equal(t, transaction.TfAllOrNothing, batch.Flags)
	require.Len(t, batch.RawTransactions, 2)

	first := innerOf(t, batch, 0)
	second := innerOf(t, batch, 1)
	requireInnerShape(t, first)
	requireInnerShape(t, second)
	require.Equal(t, uint32(startSequence+1), first["Sequence"], "the batch account's inners start one past the Batch")
	require.Equal(t, uint32(startSequence+2), second["Sequence"])

	// Each send debits the sender's spending balance, so the second proof must bind the
	// first send's remainder. Recomputing that remainder here and verifying the proof
	// against it is what proves the chain rather than the arithmetic alone.
	initialCt := spendingCiphertext(t, fixture, testAccount, testIssuanceID)
	firstTx := firstSend(t, batch, 0)
	secondTx := firstSend(t, batch, 1)

	afterFirst, err := elgamal.Subtract(initialCt, firstTx.SenderEncryptedAmount)
	require.NoError(t, err)
	require.Equal(t, uint64(initialBalance-firstAmount), decryptField(t, afterFirst, senderKey.PrivKeyHex))

	keys := sendKeys{sender: senderKey.PubKeyHex, receiver: receiverKey.PubKeyHex, issuer: issuerKey.PubKeyHex}
	requireSendBinding(t, firstTx, keys, initialCt, startSequence+1, startVersion)
	requireSendBinding(t, secondTx, keys, afterFirst, startSequence+2, startVersion+1)
}

// TestBuildBatchReceivedCreditSpentLater pins the other half of the chain: a holder receives
// a send, merges its inbox, and spends the merged balance, all in one Batch. The final send
// proves against a balance that exists only because two earlier inners in the same Batch put
// it there.
func TestBuildBatchReceivedCreditSpentLater(t *testing.T) {
	const (
		senderBalance    = 400
		receiverSpending = 50
		receiverInbox    = 10
		received         = 90
		returned         = 30
		startSequence    = 4
	)

	fixture := newBatchFixture(t).
		withIssuance(testIssuanceID).
		withHolder(testAccount, testIssuanceID, holderFixture{
			spending: amountOf(senderBalance),
			inbox:    amountOf(0),
		}).
		withHolder(testDestination, testIssuanceID, holderFixture{
			spending: amountOf(receiverSpending),
			inbox:    amountOf(receiverInbox),
		}).
		withSequence(testAccount, startSequence).
		withSequence(testDestination, 20)

	batch, err := BuildBatch(fixture.querier(), BuildBatchParams{
		Account: testAccount,
		Operations: []BatchOperation{
			sendOp(fixture, testAccount, testDestination, testIssuanceID, received),
			mergeOp(testDestination, testIssuanceID),
			sendOp(fixture, testDestination, testAccount, testIssuanceID, returned),
		},
	})
	require.NoError(t, err)
	require.Len(t, batch.RawTransactions, 3)

	// Each account's inners take consecutive sequences from its own counter, and only the
	// Batch account's start one past the Batch itself.
	require.Equal(t, uint32(startSequence+1), innerOf(t, batch, 0)["Sequence"])
	require.Equal(t, uint32(20), innerOf(t, batch, 1)["Sequence"])
	require.Equal(t, uint32(21), innerOf(t, batch, 2)["Sequence"])

	receiverKey := fixture.holderKey(testDestination, testIssuanceID)
	finalSend := firstSend(t, batch, 2)
	// The balance the last send proves against is the receiver's own spending balance plus
	// everything the merge folded in, which includes the amount the first inner sent.
	expected := uint64(receiverSpending + receiverInbox + received)
	require.Equal(t, expected, decryptField(t, mergedSpendingOf(t, fixture, batch), receiverKey.PrivKeyHex))

	senderKey := fixture.holderKey(testAccount, testIssuanceID)
	keys := sendKeys{
		sender:   receiverKey.PubKeyHex,
		receiver: senderKey.PubKeyHex,
		issuer:   fixture.issuerKey(testIssuanceID).PubKeyHex,
	}
	// An incoming send credits the inbox and leaves the spending balance alone, so it does
	// not advance the receiver's version. Only the merge does, which takes it from 0 to 1.
	requireSendBinding(t, finalSend, keys, mergedSpendingOf(t, fixture, batch), 21, 1)
}

// TestBuildBatchConvertThenSpend pins that a convert's credit is visible to the operations
// after it: the second convert is funded from what the first leaves of the public balance,
// registers no key because the first already did, and the convert-back that follows is
// checked against the confidential supply the converts raised.
func TestBuildBatchConvertThenSpend(t *testing.T) {
	const (
		publicBalance = 300
		firstConvert  = 100
		secondConvert = 150
		startSequence = 11
	)

	fixture := newBatchFixture(t).
		withIssuance(testIssuanceID).
		withHolder(testAccount, testIssuanceID, holderFixture{
			unregistered: true,
			publicAmount: publicBalance,
		}).
		withSequence(testAccount, startSequence)

	batch, err := BuildBatch(fixture.querier(), BuildBatchParams{
		Account: testAccount,
		Operations: []BatchOperation{
			convertOp(fixture, testAccount, testIssuanceID, firstConvert),
			convertOp(fixture, testAccount, testIssuanceID, secondConvert),
		},
	})
	require.NoError(t, err)

	first := innerOf(t, batch, 0)
	second := innerOf(t, batch, 1)
	// Only the first convert registers the holder key. The ledger shows no key for either,
	// so a builder reading the ledger twice would emit it twice and the second would fail.
	require.Contains(t, first, "HolderEncryptionKey")
	require.Contains(t, first, "ZKProof")
	require.NotContains(t, second, "HolderEncryptionKey")
	require.NotContains(t, second, "ZKProof")
}

// TestBuildBatchConvertFundsLaterSend pins the cross-account chain: a destination that has
// never opted into confidential balances converts inside the Batch, and the send that
// follows encrypts to the key that convert registers rather than to a ledger value that
// does not exist yet.
func TestBuildBatchConvertFundsLaterSend(t *testing.T) {
	const (
		senderBalance = 250
		destPublic    = 60
		destConvert   = 40
		sent          = 25
	)

	fixture := newBatchFixture(t).
		withIssuance(testIssuanceID).
		withHolder(testAccount, testIssuanceID, holderFixture{spending: amountOf(senderBalance)}).
		withHolder(testDestination, testIssuanceID, holderFixture{
			unregistered: true,
			publicAmount: destPublic,
		}).
		withSequence(testAccount, 5).
		withSequence(testDestination, 9)

	batch, err := BuildBatch(fixture.querier(), BuildBatchParams{
		Account: testAccount,
		Operations: []BatchOperation{
			convertOp(fixture, testDestination, testIssuanceID, destConvert),
			sendOp(fixture, testAccount, testDestination, testIssuanceID, sent),
		},
	})
	require.NoError(t, err)

	destinationKey := fixture.holderKey(testDestination, testIssuanceID)
	send := firstSend(t, batch, 1)
	require.Equal(t, uint64(sent), decryptField(t, send.DestinationEncryptedAmount, destinationKey.PrivKeyHex),
		"the send must encrypt to the key the in-batch convert registers")
}

// TestBuildBatchClawbackSeesEarlierInners pins that a clawback burns the balance the Batch
// leaves the holder rather than the one the ledger shows: the amount is decrypted from the
// predicted issuer mirror, so an earlier convert by that holder is included.
func TestBuildBatchClawbackSeesEarlierInners(t *testing.T) {
	const (
		holderSpending = 70
		holderPublic   = 200
		converted      = 30
	)

	fixture := newBatchFixture(t).
		withIssuance(testIssuerIssuanceID).
		withHolder(testDestination, testIssuerIssuanceID, holderFixture{
			spending:     amountOf(holderSpending),
			publicAmount: holderPublic,
		}).
		withSequence(testAccount, 15).
		withSequence(testDestination, 3)

	batch, err := BuildBatch(fixture.querier(), BuildBatchParams{
		Account: testAccount,
		Operations: []BatchOperation{
			convertOp(fixture, testDestination, testIssuerIssuanceID, converted),
			clawbackOp(fixture, testAccount, testDestination, testIssuerIssuanceID),
		},
	})
	require.NoError(t, err)

	clawback := innerOf(t, batch, 1)
	require.Equal(t, types.MPTPlainAmount(holderSpending+converted).String(), clawback["MPTAmount"],
		"the clawback burns the balance the earlier convert leaves")
}

// TestBuildBatchAcrossIssuancesAndAccounts pins that state is keyed per MPToken: two
// issuances and two accounts in one Batch never share a balance, a version, or a nonce.
func TestBuildBatchAcrossIssuancesAndAccounts(t *testing.T) {
	fixture := newBatchFixture(t).
		withIssuance(testIssuanceID).
		withIssuance(secondIssuanceID).
		withHolder(testAccount, testIssuanceID, holderFixture{spending: amountOf(200), version: 1}).
		withHolder(testAccount, secondIssuanceID, holderFixture{spending: amountOf(90), version: 8}).
		withHolder(testDestination, testIssuanceID, holderFixture{inbox: amountOf(0)}).
		withHolder(testDestination, secondIssuanceID, holderFixture{inbox: amountOf(0)}).
		withSequence(testAccount, 30).
		withSequence(testDestination, 60)

	batch, err := BuildBatch(fixture.querier(), BuildBatchParams{
		Account: testAccount,
		Operations: []BatchOperation{
			sendOp(fixture, testAccount, testDestination, testIssuanceID, 50),
			sendOp(fixture, testAccount, testDestination, secondIssuanceID, 40),
		},
	})
	require.NoError(t, err)

	senderKey := fixture.holderKey(testAccount, testIssuanceID)
	otherKey := fixture.holderKey(testAccount, secondIssuanceID)
	keys := sendKeys{
		sender:   senderKey.PubKeyHex,
		receiver: fixture.holderKey(testDestination, testIssuanceID).PubKeyHex,
		issuer:   fixture.issuerKey(testIssuanceID).PubKeyHex,
	}
	otherKeys := sendKeys{
		sender:   otherKey.PubKeyHex,
		receiver: fixture.holderKey(testDestination, secondIssuanceID).PubKeyHex,
		issuer:   fixture.issuerKey(secondIssuanceID).PubKeyHex,
	}
	// Each send binds its own MPToken's version, untouched by the other issuance.
	requireSendBinding(t, firstSend(t, batch, 0), keys, spendingCiphertext(t, fixture, testAccount, testIssuanceID), 31, 1)
	requireSendBinding(t, firstSend(t, batch, 1), otherKeys, spendingCiphertext(t, fixture, testAccount, secondIssuanceID), 32, 8)
}

// TestBuildBatchAuditedIssuance pins that an auditing issuance's third mirror balance is
// carried through every transition: the chained second send still verifies, which it cannot
// if the auditor mirror was predicted wrongly or skipped.
func TestBuildBatchAuditedIssuance(t *testing.T) {
	fixture := newBatchFixture(t).
		withAuditedIssuance(testIssuanceID).
		withHolder(testAccount, testIssuanceID, holderFixture{spending: amountOf(300)}).
		withHolder(testDestination, testIssuanceID, holderFixture{inbox: amountOf(5)}).
		withSequence(testAccount, 2)

	batch, err := BuildBatch(fixture.querier(), BuildBatchParams{
		Account: testAccount,
		Operations: []BatchOperation{
			sendOp(fixture, testAccount, testDestination, testIssuanceID, 40),
			sendOp(fixture, testAccount, testDestination, testIssuanceID, 60),
		},
	})
	require.NoError(t, err)

	first := firstSend(t, batch, 0)
	require.NotNil(t, first.AuditorEncryptedAmount)

	auditor := fixture.issuances[testIssuanceID].auditor
	require.NotNil(t, auditor)
	require.Equal(t, uint64(40), decryptField(t, *first.AuditorEncryptedAmount, auditor.PrivKeyHex))

	initialCt := spendingCiphertext(t, fixture, testAccount, testIssuanceID)
	afterFirst, err := elgamal.Subtract(initialCt, first.SenderEncryptedAmount)
	require.NoError(t, err)
	keys := sendKeys{
		sender:   fixture.holderKey(testAccount, testIssuanceID).PubKeyHex,
		receiver: fixture.holderKey(testDestination, testIssuanceID).PubKeyHex,
		issuer:   fixture.issuerKey(testIssuanceID).PubKeyHex,
		auditor:  auditor.PubKeyHex,
	}
	requireSendBinding(t, firstSend(t, batch, 1), keys, afterFirst, 4, 1)
}

// TestBuildBatchTicketNonces pins nonce allocation when tickets are in play: a ticketed
// inner takes no sequence from its account's counter, and a ticketed outer Batch leaves the
// account's own inners starting at its current sequence rather than one past it.
func TestBuildBatchTicketNonces(t *testing.T) {
	const (
		accountSequence = 12
		outerTicket     = 900
		innerTicket     = 901
	)

	fixture := newBatchFixture(t).
		withIssuance(testIssuanceID).
		withHolder(testAccount, testIssuanceID, holderFixture{spending: amountOf(500)}).
		withHolder(testDestination, testIssuanceID, holderFixture{inbox: amountOf(0)}).
		withSequence(testAccount, accountSequence)

	ticketed := sendOp(fixture, testAccount, testDestination, testIssuanceID, 10)
	ticketed.TicketSequence = innerTicket

	batch, err := BuildBatch(fixture.querier(), BuildBatchParams{
		TxOptions: TxOptions{TicketSequence: outerTicket},
		Account:   testAccount,
		Operations: []BatchOperation{
			ticketed,
			sendOp(fixture, testAccount, testDestination, testIssuanceID, 20),
		},
	})
	require.NoError(t, err)

	require.Equal(t, uint32(outerTicket), batch.TicketSequence)
	require.Zero(t, batch.Sequence)

	first := innerOf(t, batch, 0)
	require.Equal(t, uint32(innerTicket), first["TicketSequence"])
	require.Equal(t, uint32(0), first["Sequence"])
	// The Batch spent a Ticket rather than the account sequence, so the first sequenced
	// inner takes the sequence the Batch would otherwise have consumed.
	require.Equal(t, uint32(accountSequence), innerOf(t, batch, 1)["Sequence"])

	// A proof on a ticketed inner binds the ticket, because rippled hashes the sequence
	// proxy rather than the account sequence.
	keys := sendKeys{
		sender:   fixture.holderKey(testAccount, testIssuanceID).PubKeyHex,
		receiver: fixture.holderKey(testDestination, testIssuanceID).PubKeyHex,
		issuer:   fixture.issuerKey(testIssuanceID).PubKeyHex,
	}
	requireSendBinding(t, firstSend(t, batch, 0), keys, spendingCiphertext(t, fixture, testAccount, testIssuanceID), innerTicket, 0)
}

// TestBuildBatchPlainInner pins that a supported ready-made transaction is carried through
// untouched apart from the Batch shaping and the sequence it is owed.
func TestBuildBatchPlainInner(t *testing.T) {
	fixture := newBatchFixture(t).
		withIssuance(testIssuanceID).
		withHolder(testAccount, testIssuanceID, holderFixture{spending: amountOf(100)}).
		withHolder(testDestination, testIssuanceID, holderFixture{inbox: amountOf(0)}).
		withSequence(testAccount, 40)

	domain := "6578616D706C652E636F6D"
	batch, err := BuildBatch(fixture.querier(), BuildBatchParams{
		Account: testAccount,
		Operations: []BatchOperation{
			TransactionOp{Tx: &transaction.AccountSet{
				BaseTx: transaction.BaseTx{Account: types.Address(testAccount), TransactionType: transaction.AccountSetTx},
				Domain: &domain,
			}},
			sendOp(fixture, testAccount, testDestination, testIssuanceID, 10),
		},
	})
	require.NoError(t, err)

	plain := innerOf(t, batch, 0)
	requireInnerShape(t, plain)
	require.Equal(t, transaction.AccountSetTx.String(), plain["TransactionType"])
	require.Equal(t, domain, plain["Domain"])
	require.Equal(t, uint32(41), plain["Sequence"])
	require.Equal(t, uint32(42), innerOf(t, batch, 1)["Sequence"])
}

// TestBuildBatchOneValidatedLedger pins that every state read of one assembly is bound to a
// single validated ledger, which is what keeps two inners' proofs from mixing ledgers.
func TestBuildBatchOneValidatedLedger(t *testing.T) {
	fixture := newBatchFixture(t).
		withIssuance(testIssuanceID).
		withHolder(testAccount, testIssuanceID, holderFixture{spending: amountOf(100)}).
		withHolder(testDestination, testIssuanceID, holderFixture{inbox: amountOf(0)}).
		withSequence(testAccount, 1)

	querier := fixture.querier()
	_, err := BuildBatch(querier, BuildBatchParams{
		Account: testAccount,
		Operations: []BatchOperation{
			sendOp(fixture, testAccount, testDestination, testIssuanceID, 10),
			sendOp(fixture, testAccount, testDestination, testIssuanceID, 20),
		},
	})
	require.NoError(t, err)

	validated := 0
	for _, request := range querier.requests {
		if request.LedgerIndex == common.Current {
			continue
		}
		validated++
		if request.LedgerHash != "" {
			require.Equal(t, mockLedgerHash, request.LedgerHash)
			continue
		}
		require.Equal(t, mockLedgerIndex, request.LedgerIndex)
	}
	require.Positive(t, validated)
}

// TestBuildBatchRejectsUnpredictableChains covers the chains the assembler refuses rather
// than emitting a proof the ledger would reject, and the operation shapes it cannot own.
func TestBuildBatchRejectsUnpredictableChains(t *testing.T) {
	tests := []struct {
		name       string
		flags      uint32
		operations func(f *batchFixture) []BatchOperation
		wantErr    error
	}{
		{
			// A second merge folds the reset inbox into the spending balance, which carries
			// the reset forward: the send after it proves against a balance the assembler
			// can no longer name.
			name: "second merge leaves a spending balance no later send can prove against",
			operations: func(f *batchFixture) []BatchOperation {
				return []BatchOperation{
					mergeOp(testDestination, testIssuanceID),
					mergeOp(testDestination, testIssuanceID),
					sendOp(f, testDestination, testAccount, testIssuanceID, 1),
				}
			},
			wantErr: ErrBatchUnpredictableState,
		},
		{
			// A holder's first convert initializes its spending balance to the canonical
			// encrypted zero, so the holder can merge in the same Batch but cannot spend.
			name: "first convert then spend in the same Batch",
			operations: func(f *batchFixture) []BatchOperation {
				return []BatchOperation{
					convertOp(f, testDelegate, testIssuanceID, 0),
					sendOp(f, testDelegate, testAccount, testIssuanceID, 1),
				}
			},
			wantErr: ErrBatchUnpredictableState,
		},
		{
			name: "clawback then send reads the reset balances",
			operations: func(f *batchFixture) []BatchOperation {
				return []BatchOperation{
					clawbackOp(f, testAccount, testDestination, testIssuerIssuanceID),
					sendOp(f, testDestination, testDelegate, testIssuerIssuanceID, 5),
				}
			},
			wantErr: ErrBatchUnpredictableState,
		},
		{
			name: "clawback then clawback reads the reset mirror",
			operations: func(f *batchFixture) []BatchOperation {
				return []BatchOperation{
					clawbackOp(f, testAccount, testDestination, testIssuerIssuanceID),
					clawbackOp(f, testAccount, testDestination, testIssuerIssuanceID),
				}
			},
			wantErr: ErrBatchUnpredictableState,
		},
		{
			name:  "until failure mode",
			flags: transaction.TfUntilFailure,
			operations: func(f *batchFixture) []BatchOperation {
				return []BatchOperation{
					sendOp(f, testAccount, testDestination, testIssuanceID, 10),
					sendOp(f, testAccount, testDestination, testIssuanceID, 20),
				}
			},
			wantErr: ErrBatchModeNotSupported,
		},
		{
			name:  "independent mode",
			flags: transaction.TfIndependent,
			operations: func(f *batchFixture) []BatchOperation {
				return []BatchOperation{
					sendOp(f, testAccount, testDestination, testIssuanceID, 10),
					sendOp(f, testAccount, testDestination, testIssuanceID, 20),
				}
			},
			wantErr: ErrBatchModeNotSupported,
		},
		{
			name: "confidential operation with its own sequence",
			operations: func(f *batchFixture) []BatchOperation {
				op := sendOp(f, testAccount, testDestination, testIssuanceID, 10)
				op.Sequence = 99
				return []BatchOperation{op, sendOp(f, testAccount, testDestination, testIssuanceID, 20)}
			},
			wantErr: ErrBatchInnerSequenceSet,
		},
		{
			name: "unsupported plain inner",
			operations: func(f *batchFixture) []BatchOperation {
				holder := types.Address(testDestination)
				return []BatchOperation{
					TransactionOp{Tx: &transaction.MPTokenAuthorize{
						BaseTx:            transaction.BaseTx{Account: types.Address(testAccount), TransactionType: transaction.MPTokenAuthorizeTx},
						MPTokenIssuanceID: testIssuanceID,
						Holder:            &holder,
					}},
					sendOp(f, testAccount, testDestination, testIssuanceID, 10),
				}
			},
			wantErr: ErrBatchInnerNotSupported,
		},
		{
			name: "nil operation",
			operations: func(f *batchFixture) []BatchOperation {
				return []BatchOperation{nil, sendOp(f, testAccount, testDestination, testIssuanceID, 10)}
			},
			wantErr: ErrBatchMissingOperation,
		},
		{
			name: "destination never opted in",
			operations: func(f *batchFixture) []BatchOperation {
				return []BatchOperation{
					sendOp(f, testAccount, testDelegate, testIssuanceID, 10),
					sendOp(f, testAccount, testDestination, testIssuanceID, 20),
				}
			},
			wantErr: ErrReceiverNotOptedIn,
		},
		{
			name: "second convert overdraws the public balance",
			operations: func(f *batchFixture) []BatchOperation {
				return []BatchOperation{
					convertOp(f, testAccount, testIssuanceID, 60),
					convertOp(f, testAccount, testIssuanceID, 60),
				}
			},
			wantErr: ErrInsufficientBalance,
		},
		{
			name: "second send overdraws the chained balance",
			operations: func(f *batchFixture) []BatchOperation {
				return []BatchOperation{
					sendOp(f, testAccount, testDestination, testIssuanceID, 90),
					sendOp(f, testAccount, testDestination, testIssuanceID, 90),
				}
			},
			wantErr: ErrInsufficientBalance,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newBatchFixture(t).
				withIssuance(testIssuanceID).
				withIssuance(testIssuerIssuanceID).
				withHolder(testAccount, testIssuanceID, holderFixture{
					spending:     amountOf(100),
					inbox:        amountOf(0),
					publicAmount: 100,
				}).
				withHolder(testDestination, testIssuanceID, holderFixture{
					spending: amountOf(10),
					inbox:    amountOf(10),
				}).
				withHolder(testDelegate, testIssuanceID, holderFixture{unregistered: true}).
				withHolder(testDestination, testIssuerIssuanceID, holderFixture{spending: amountOf(40)}).
				withHolder(testDelegate, testIssuerIssuanceID, holderFixture{inbox: amountOf(0)}).
				withSequence(testAccount, 5).
				withSequence(testDestination, 5).
				withSequence(testDelegate, 5)

			_, err := BuildBatch(fixture.querier(), BuildBatchParams{
				Account:    testAccount,
				Operations: tt.operations(fixture),
				Flags:      tt.flags,
			})
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// TestBuildBatchOperationCount pins the bounds rippled puts on a Batch, checked before any
// ledger read so an impossible size costs nothing.
func TestBuildBatchOperationCount(t *testing.T) {
	fixture := newBatchFixture(t).
		withIssuance(testIssuanceID).
		withHolder(testAccount, testIssuanceID, holderFixture{spending: amountOf(1000)}).
		withHolder(testDestination, testIssuanceID, holderFixture{inbox: amountOf(0)})

	tests := []struct {
		name  string
		count int
	}{
		{name: "none", count: 0},
		{name: "one", count: 1},
		{name: "nine", count: 9},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			operations := make([]BatchOperation, 0, tt.count)
			for range tt.count {
				operations = append(operations, sendOp(fixture, testAccount, testDestination, testIssuanceID, 1))
			}

			querier := fixture.querier()
			_, err := BuildBatch(querier, BuildBatchParams{Account: testAccount, Operations: operations})
			require.ErrorIs(t, err, ErrBatchOperationCount)
			require.Empty(t, querier.requests, "an impossible size must cost no ledger reads")
			require.Empty(t, querier.accounts)
		})
	}
}

// TestBuildBatchEightOperations pins that the upper bound is inclusive and that a full Batch
// of chained spends assembles.
func TestBuildBatchEightOperations(t *testing.T) {
	fixture := newBatchFixture(t).
		withIssuance(testIssuanceID).
		withHolder(testAccount, testIssuanceID, holderFixture{spending: amountOf(1000)}).
		withHolder(testDestination, testIssuanceID, holderFixture{inbox: amountOf(0)}).
		withSequence(testAccount, 1)

	operations := make([]BatchOperation, 0, maxBatchOperations)
	for range maxBatchOperations {
		operations = append(operations, sendOp(fixture, testAccount, testDestination, testIssuanceID, 10))
	}

	batch, err := BuildBatch(fixture.querier(), BuildBatchParams{Account: testAccount, Operations: operations})
	require.NoError(t, err)
	require.Len(t, batch.RawTransactions, maxBatchOperations)
	for index := range batch.RawTransactions {
		require.Equal(t, uint32(2+index), innerOf(t, batch, index)["Sequence"])
	}
}

// TestBuildBatchOuterValidation covers the outer Batch fields the assembler rejects before
// touching the ledger.
func TestBuildBatchOuterValidation(t *testing.T) {
	fixture := newBatchFixture(t).
		withIssuance(testIssuanceID).
		withHolder(testAccount, testIssuanceID, holderFixture{spending: amountOf(100)}).
		withHolder(testDestination, testIssuanceID, holderFixture{inbox: amountOf(0)})

	operations := []BatchOperation{
		sendOp(fixture, testAccount, testDestination, testIssuanceID, 10),
		sendOp(fixture, testAccount, testDestination, testIssuanceID, 20),
	}

	tests := []struct {
		name    string
		params  BuildBatchParams
		wantErr error
	}{
		{
			name:    "missing account",
			params:  BuildBatchParams{Operations: operations},
			wantErr: ErrMissingAccount,
		},
		{
			name:    "invalid account",
			params:  BuildBatchParams{Account: "not-an-address", Operations: operations},
			wantErr: ErrInvalidAccount,
		},
		{
			name:    "zero account",
			params:  BuildBatchParams{Account: zeroClassicAccount, Operations: operations},
			wantErr: ErrInvalidAccount,
		},
		{
			name: "conflicting outer nonce",
			params: BuildBatchParams{
				TxOptions:  TxOptions{Sequence: 3, TicketSequence: 4},
				Account:    testAccount,
				Operations: operations,
			},
			wantErr: ErrConflictingNonce,
		},
		{
			name: "delegated batch",
			params: BuildBatchParams{
				TxOptions:  TxOptions{Delegate: testDelegate},
				Account:    testAccount,
				Operations: operations,
			},
			wantErr: ErrDelegateNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildBatch(fixture.querier(), tt.params)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// TestBuildBatchExplicitOuterSequence pins that a caller-supplied outer sequence is honored
// and that the account's inners follow from it without a second account query.
func TestBuildBatchExplicitOuterSequence(t *testing.T) {
	fixture := newBatchFixture(t).
		withIssuance(testIssuanceID).
		withHolder(testAccount, testIssuanceID, holderFixture{spending: amountOf(200)}).
		withHolder(testDestination, testIssuanceID, holderFixture{inbox: amountOf(0)}).
		withSequence(testAccount, 99)

	querier := fixture.querier()
	batch, err := BuildBatch(querier, BuildBatchParams{
		TxOptions: TxOptions{Sequence: 50},
		Account:   testAccount,
		Operations: []BatchOperation{
			sendOp(fixture, testAccount, testDestination, testIssuanceID, 10),
			sendOp(fixture, testAccount, testDestination, testIssuanceID, 20),
		},
	})
	require.NoError(t, err)

	require.Equal(t, uint32(50), batch.Sequence)
	require.Equal(t, uint32(51), innerOf(t, batch, 0)["Sequence"])
	require.Equal(t, uint32(52), innerOf(t, batch, 1)["Sequence"])
	require.Empty(t, querier.accounts, "an explicit outer sequence answers for the batch account too")
}

// TestIsSupportedInnerTransactionType pins the allowlist: the types that cannot disturb a
// prediction are accepted, and the ones that can are not.
func TestIsSupportedInnerTransactionType(t *testing.T) {
	tests := []struct {
		txType    transaction.TxType
		supported bool
	}{
		{txType: transaction.AccountSetTx, supported: true},
		{txType: transaction.TicketCreateTx, supported: true},
		{txType: transaction.CredentialAcceptTx, supported: true},
		{txType: transaction.TrustSetTx, supported: true},
		{txType: transaction.PaymentTx},
		{txType: transaction.MPTokenAuthorizeTx},
		{txType: transaction.MPTokenIssuanceSetTx},
		{txType: transaction.ConfidentialMPTSendTx},
		{txType: transaction.BatchTx},
		{txType: transaction.AccountDeleteTx},
	}

	for _, tt := range tests {
		t.Run(tt.txType.String(), func(t *testing.T) {
			require.Equal(t, tt.supported, IsSupportedInnerTransactionType(tt.txType))
		})
	}
}

// TestBuildBatchHolderPreflight pins that the locked and authorized conditions the
// transactors check are decided before a proof is generated, and that a clawback is exempt
// from both, as the clawback transactor is.
func TestBuildBatchHolderPreflight(t *testing.T) {
	t.Run("locked sender", func(t *testing.T) {
		fixture := newBatchFixture(t).
			withIssuance(testIssuanceID).
			withHolder(testAccount, testIssuanceID, holderFixture{
				spending: amountOf(100),
				flags:    ledgerentries.LsfMPTLocked,
			}).
			withHolder(testDestination, testIssuanceID, holderFixture{inbox: amountOf(0)})

		_, err := BuildBatch(fixture.querier(), BuildBatchParams{
			Account: testAccount,
			Operations: []BatchOperation{
				sendOp(fixture, testAccount, testDestination, testIssuanceID, 10),
				sendOp(fixture, testAccount, testDestination, testIssuanceID, 20),
			},
		})
		require.ErrorIs(t, err, ErrHolderLocked)
	})

	t.Run("locked clawback holder", func(t *testing.T) {
		fixture := newBatchFixture(t).
			withIssuance(testIssuerIssuanceID).
			withHolder(testDestination, testIssuerIssuanceID, holderFixture{
				spending: amountOf(40),
				flags:    ledgerentries.LsfMPTLocked,
			}).
			withSequence(testAccount, 3)

		batch, err := BuildBatch(fixture.querier(), BuildBatchParams{
			Account: testAccount,
			Operations: []BatchOperation{
				clawbackOp(fixture, testAccount, testDestination, testIssuerIssuanceID),
				TransactionOp{Tx: &transaction.AccountSet{
					BaseTx: transaction.BaseTx{Account: types.Address(testAccount), TransactionType: transaction.AccountSetTx},
				}},
			},
		})
		require.NoError(t, err, "an issuer must be able to claw back from a holder it locked")
		require.Equal(t, types.MPTPlainAmount(40).String(), innerOf(t, batch, 0)["MPTAmount"])
	})
}

// firstSend decodes one built inner back into the typed transaction the assertions read. The
// assembler hands back flattened inners, because that is what a Batch carries.
func firstSend(t *testing.T, batch *transaction.Batch, index int) *transaction.ConfidentialMPTSend {
	t.Helper()

	inner := innerOf(t, batch, index)
	require.Equal(t, transaction.ConfidentialMPTSendTx.String(), inner["TransactionType"])

	tx := &transaction.ConfidentialMPTSend{
		BaseTx: transaction.BaseTx{
			Account:         types.Address(inner["Account"].(string)),
			TransactionType: transaction.ConfidentialMPTSendTx,
		},
		MPTokenIssuanceID:          inner["MPTokenIssuanceID"].(string),
		Destination:                types.Address(inner["Destination"].(string)),
		SenderEncryptedAmount:      inner["SenderEncryptedAmount"].(string),
		DestinationEncryptedAmount: inner["DestinationEncryptedAmount"].(string),
		IssuerEncryptedAmount:      inner["IssuerEncryptedAmount"].(string),
		ZKProof:                    inner["ZKProof"].(string),
		AmountCommitment:           inner["AmountCommitment"].(string),
		BalanceCommitment:          inner["BalanceCommitment"].(string),
	}
	if auditor, ok := inner["AuditorEncryptedAmount"].(string); ok {
		tx.AuditorEncryptedAmount = &auditor
	}
	return tx
}

// spendingCiphertext reads the spending balance the fixture ledger carries for one holder,
// which is the state the first inner on that MPToken proves against.
func spendingCiphertext(t *testing.T, fixture *batchFixture, holder, issuanceID string) string {
	t.Helper()

	index, err := xrplhash.MPToken(issuanceID, holder)
	require.NoError(t, err)
	entry := fixture.entries[index]
	ciphertext, ok := entry["ConfidentialBalanceSpending"].(string)
	require.True(t, ok, "fixture holder has no spending balance")
	return ciphertext
}

// mergedSpendingOf recomputes the destination's spending balance after the send and merge in
// TestBuildBatchReceivedCreditSpentLater, the way the transactor computes it: the received
// amount is re-randomized into the inbox, then the whole inbox is folded into spending.
func mergedSpendingOf(t *testing.T, fixture *batchFixture, batch *transaction.Batch) string {
	t.Helper()

	send := firstSend(t, batch, 0)
	challenge, err := sendChallenge(send.ZKProof)
	require.NoError(t, err)

	destinationKey := fixture.holderKey(testDestination, testIssuanceID)
	credited, err := rerandomize(send.DestinationEncryptedAmount, destinationKey.PubKeyHex, challenge)
	require.NoError(t, err)

	index, err := xrplhash.MPToken(testIssuanceID, testDestination)
	require.NoError(t, err)
	entry := fixture.entries[index]

	inbox, err := elgamal.Add(entry["ConfidentialBalanceInbox"].(string), credited)
	require.NoError(t, err)
	merged, err := elgamal.Add(entry["ConfidentialBalanceSpending"].(string), inbox)
	require.NoError(t, err)
	return merged
}

// TestBuildBatchSendThenConvertBack pins a chain across two operation types on one MPToken:
// a send debits the balance and bumps the version, and the convert-back after it must prove
// against exactly what the send leaves. It also pins the running confidential supply, which
// a convert earlier in the Batch raises so the convert-back is not rejected against the
// pre-batch figure.
func TestBuildBatchSendThenConvertBack(t *testing.T) {
	const (
		initialBalance = 300
		publicBalance  = 500
		converted      = 200
		sent           = 120
		revealed       = 90
		startSequence  = 21
		startVersion   = 6
	)

	fixture := newBatchFixture(t).
		withIssuance(testIssuanceID).
		withHolder(testAccount, testIssuanceID, holderFixture{
			spending:     amountOf(initialBalance),
			version:      startVersion,
			publicAmount: publicBalance,
		}).
		withHolder(testDestination, testIssuanceID, holderFixture{inbox: amountOf(0)}).
		withSequence(testAccount, startSequence)

	holder := fixture.holderKey(testAccount, testIssuanceID)
	batch, err := BuildBatch(fixture.querier(), BuildBatchParams{
		Account: testAccount,
		Operations: []BatchOperation{
			convertOp(fixture, testAccount, testIssuanceID, converted),
			sendOp(fixture, testAccount, testDestination, testIssuanceID, sent),
			convertBackOp(fixture, testAccount, testIssuanceID, revealed),
		},
	})
	require.NoError(t, err)

	send := firstSend(t, batch, 1)
	convertBack := convertBackInner(t, batch, 2)

	// The convert credited the inbox, so the send still spends the pre-batch balance, and
	// the convert-back spends what the send leaves of it.
	initialCt := spendingCiphertext(t, fixture, testAccount, testIssuanceID)
	afterSend, err := elgamal.Subtract(initialCt, send.SenderEncryptedAmount)
	require.NoError(t, err)
	require.Equal(t, uint64(initialBalance-sent), decryptField(t, afterSend, holder.PrivKeyHex))

	keys := sendKeys{
		sender:   holder.PubKeyHex,
		receiver: fixture.holderKey(testDestination, testIssuanceID).PubKeyHex,
		issuer:   fixture.issuerKey(testIssuanceID).PubKeyHex,
	}
	requireSendBinding(t, send, keys, initialCt, startSequence+2, startVersion)
	// Only the send advanced the version; the convert before it credited the inbox and left
	// both the spending balance and the version alone.
	requireConvertBackBinding(t, convertBack, holder.PubKeyHex, afterSend, startSequence+3, startVersion+1)
}

// TestBuildBatchClawbackBinding pins that a clawback's proof is bound to the issuer mirror
// balance the earlier inners leave, and to the amount decrypted from it.
func TestBuildBatchClawbackBinding(t *testing.T) {
	const (
		holderSpending = 80
		holderPublic   = 150
		converted      = 45
		issuerSequence = 17
	)

	fixture := newBatchFixture(t).
		withIssuance(testIssuerIssuanceID).
		withHolder(testDestination, testIssuerIssuanceID, holderFixture{
			spending:     amountOf(holderSpending),
			publicAmount: holderPublic,
		}).
		withSequence(testAccount, issuerSequence).
		withSequence(testDestination, 8)

	batch, err := BuildBatch(fixture.querier(), BuildBatchParams{
		Account: testAccount,
		Operations: []BatchOperation{
			convertOp(fixture, testDestination, testIssuerIssuanceID, converted),
			clawbackOp(fixture, testAccount, testDestination, testIssuerIssuanceID),
		},
	})
	require.NoError(t, err)

	convert := innerOf(t, batch, 0)
	issuerMirror := issuerMirrorOf(t, fixture, testDestination, testIssuerIssuanceID)
	predicted, err := elgamal.Add(issuerMirror, convert["IssuerEncryptedAmount"].(string))
	require.NoError(t, err)

	issuer := fixture.issuerKey(testIssuerIssuanceID)
	require.Equal(t, uint64(holderSpending+converted), decryptField(t, predicted, issuer.PrivKeyHex))
	requireClawbackBinding(t, clawbackInner(t, batch, 1), issuer.PubKeyHex, predicted, issuerSequence+1)
}

// convertBackInner decodes one built ConfidentialMPTConvertBack inner.
func convertBackInner(t *testing.T, batch *transaction.Batch, index int) *transaction.ConfidentialMPTConvertBack {
	t.Helper()

	inner := innerOf(t, batch, index)
	require.Equal(t, transaction.ConfidentialMPTConvertBackTx.String(), inner["TransactionType"])

	amount, err := strconv.ParseUint(inner["MPTAmount"].(string), 10, 64)
	require.NoError(t, err)
	return &transaction.ConfidentialMPTConvertBack{
		BaseTx: transaction.BaseTx{
			Account:         types.Address(inner["Account"].(string)),
			TransactionType: transaction.ConfidentialMPTConvertBackTx,
		},
		MPTokenIssuanceID: inner["MPTokenIssuanceID"].(string),
		MPTAmount:         types.MPTPlainAmount(amount),
		BalanceCommitment: inner["BalanceCommitment"].(string),
		ZKProof:           inner["ZKProof"].(string),
	}
}

// clawbackInner decodes one built ConfidentialMPTClawback inner.
func clawbackInner(t *testing.T, batch *transaction.Batch, index int) *transaction.ConfidentialMPTClawback {
	t.Helper()

	inner := innerOf(t, batch, index)
	require.Equal(t, transaction.ConfidentialMPTClawbackTx.String(), inner["TransactionType"])

	amount, err := strconv.ParseUint(inner["MPTAmount"].(string), 10, 64)
	require.NoError(t, err)
	return &transaction.ConfidentialMPTClawback{
		BaseTx: transaction.BaseTx{
			Account:         types.Address(inner["Account"].(string)),
			TransactionType: transaction.ConfidentialMPTClawbackTx,
		},
		MPTokenIssuanceID: inner["MPTokenIssuanceID"].(string),
		Holder:            types.Address(inner["Holder"].(string)),
		MPTAmount:         types.MPTPlainAmount(amount),
		ZKProof:           inner["ZKProof"].(string),
	}
}

// issuerMirrorOf reads the issuer mirror balance the fixture ledger carries for one holder.
func issuerMirrorOf(t *testing.T, fixture *batchFixture, holder, issuanceID string) string {
	t.Helper()

	index, err := xrplhash.MPToken(issuanceID, holder)
	require.NoError(t, err)
	mirror, ok := fixture.entries[index]["IssuerEncryptedBalance"].(string)
	require.True(t, ok, "fixture holder has no issuer mirror balance")
	return mirror
}

// TestBuildBatchUnreadableBalancesStillUsable pins the other side of the
// ErrBatchUnpredictableState limit: a field an earlier inner left as the canonical encrypted
// zero still exists, and an inner that needs only its existence builds. The transactor
// credits a destination's inbox and folds a merge's balances homomorphically without reading
// either, so refusing these would deny Batches the ledger accepts.
func TestBuildBatchUnreadableBalancesStillUsable(t *testing.T) {
	newFixture := func(t *testing.T) *batchFixture {
		t.Helper()
		return newBatchFixture(t).
			withIssuance(testIssuanceID).
			withHolder(testAccount, testIssuanceID, holderFixture{
				spending:     amountOf(100),
				inbox:        amountOf(0),
				publicAmount: 50,
			}).
			withHolder(testDestination, testIssuanceID, holderFixture{
				spending: amountOf(10),
				inbox:    amountOf(10),
			}).
			withHolder(testDelegate, testIssuanceID, holderFixture{unregistered: true, publicAmount: 20}).
			withSequence(testAccount, 5).
			withSequence(testDestination, 5).
			withSequence(testDelegate, 5)
	}

	tests := []struct {
		name       string
		operations func(f *batchFixture) []BatchOperation
	}{
		{
			// The merge resets the destination's inbox, and the send credits it without
			// reading it.
			name: "receive after a merge reset the inbox",
			operations: func(f *batchFixture) []BatchOperation {
				return []BatchOperation{
					mergeOp(testDestination, testIssuanceID),
					sendOp(f, testAccount, testDestination, testIssuanceID, 10),
				}
			},
		},
		{
			// The second merge folds a reset inbox into the spending balance, which the
			// transactor does homomorphically without reading either side.
			name: "merge twice",
			operations: func(_ *batchFixture) []BatchOperation {
				return []BatchOperation{
					mergeOp(testDestination, testIssuanceID),
					mergeOp(testDestination, testIssuanceID),
				}
			},
		},
		{
			// A first convert initializes the spending balance, which is what makes the
			// merge after it possible at all.
			name: "merge after a first convert",
			operations: func(f *batchFixture) []BatchOperation {
				return []BatchOperation{
					convertOp(f, testDelegate, testIssuanceID, 20),
					mergeOp(testDelegate, testIssuanceID),
				}
			},
		},
		{
			// A first convert registers the holder key and initializes the inbox to the
			// transaction's own ciphertext, so the send that follows both encrypts to that
			// key and credits a balance the assembler can still follow.
			name: "send to a holder that converted earlier in the Batch",
			operations: func(f *batchFixture) []BatchOperation {
				return []BatchOperation{
					convertOp(f, testDelegate, testIssuanceID, 20),
					sendOp(f, testAccount, testDelegate, testIssuanceID, 10),
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newFixture(t)
			batch, err := BuildBatch(fixture.querier(), BuildBatchParams{
				Account:    testAccount,
				Operations: tt.operations(fixture),
			})
			require.NoError(t, err)
			require.Len(t, batch.RawTransactions, 2)
		})
	}
}
