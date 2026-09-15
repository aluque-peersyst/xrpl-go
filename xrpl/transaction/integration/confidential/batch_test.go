//go:build cgo && !js && !wasip1 && !tinygo && !gofuzz && (linux || darwin) && (amd64 || arm64)

package confidential

import (
	"testing"

	"github.com/Peersyst/xrpl-go/confidential/builder"
	"github.com/Peersyst/xrpl-go/confidential/elgamal"
	"github.com/Peersyst/xrpl-go/xrpl/queries/transactions"
	"github.com/Peersyst/xrpl-go/xrpl/rpc"
	"github.com/Peersyst/xrpl-go/xrpl/testutil/integration"
	"github.com/Peersyst/xrpl-go/xrpl/transaction"
	"github.com/Peersyst/xrpl-go/xrpl/wallet"
	"github.com/Peersyst/xrpl-go/xrpl/websocket"
	"github.com/stretchr/testify/require"
)

// Amounts for the dependent-batch scenario. Each is distinct so a balance that ends up on
// the wrong side of a split, or a credit counted twice, reads as a wrong number rather than
// as a coincidence.
const (
	batchSenderFunding   uint64 = 200
	batchReceiverFunding uint64 = 40
	batchFirstSend       uint64 = 30
	batchSecondSend      uint64 = 25
	batchReturnSend      uint64 = 11
)

// batchSearchRange bounds every decryption this scenario runs. The issuance cannot hold more
// than issuanceMaximumAmount, so nothing here can fall outside it.
func batchSearchRange() elgamal.AmountRange {
	return elgamal.AmountRange{Low: 0, High: uint64(issuanceMaximumAmount)}
}

// testIntegrationConfidentialMPTDependentBatch submits one Batch whose inners depend on each
// other, which is the case no sequence of standalone builders can produce: every proof after
// the first binds a balance and a version that exist only because an earlier inner in the
// same Batch put them there.
//
// The chain is deliberately the hardest one the assembler supports:
//
//  1. sender sends to receiver.
//  2. sender sends to receiver again, proving against the balance and version inner 1 leaves.
//  3. receiver merges its inbox, folding in both credits.
//  4. receiver sends back to sender, proving against the balance inner 3 leaves.
//
// Inner 4 is what makes this a test of the predictions rather than of the arithmetic. The
// transactor does not credit a destination with the ciphertext on the wire: it re-randomizes
// each credited ciphertext under the recipient's, the issuer's, and the auditor's keys with
// the send proof's own challenge before adding it. A client that predicts the credit without
// reproducing that re-randomization computes a ciphertext that decrypts to the right amount
// and is still not the one on the ledger, so inner 4's proof would be rejected with
// tecBAD_PROOF. The Batch is all-or-nothing, so that takes the whole Batch down and the
// scenario fails rather than quietly half-applying.
//
// The issuance registers an auditor, so all three mirror-balance predictions are exercised
// rather than just the issuer's.
func testIntegrationConfidentialMPTDependentBatch(t *testing.T, client confidentialClient) {
	runner := integration.NewRunner(t, client, &integration.RunnerConfig{WalletCount: 3})
	err := runner.Setup()
	require.NoError(t, err)
	defer runner.Teardown()

	issuer := runner.GetWallet(0)
	sender := runner.GetWallet(1)
	receiver := runner.GetWallet(2)

	auditorKey := generateKey(t)
	config := issuanceConfig{issuerKey: generateKey(t), auditorKey: &auditorKey}
	senderKey := generateKey(t)
	receiverKey := generateKey(t)

	issuanceID := createIssuance(t, runner, client, issuer, config)
	authorizeHolder(t, runner, issuer, sender, issuanceID)
	authorizeHolder(t, runner, issuer, receiver, issuanceID)
	fundHolder(t, runner, issuer, sender, issuanceID, batchSenderFunding)
	fundHolder(t, runner, issuer, receiver, issuanceID, batchReceiverFunding)

	// Both holders enter the Batch with a spendable confidential balance, which takes a
	// convert and a merge each. A convert credits the inbox, and only a merge moves it into
	// the spending balance a send can prove against.
	convertAndMerge(t, runner, client, sender, issuanceID, senderKey, batchSenderFunding)
	convertAndMerge(t, runner, client, receiver, issuanceID, receiverKey, batchReceiverFunding)

	senderAddress := sender.GetAddress().String()
	receiverAddress := receiver.GetAddress().String()

	batch, err := builder.BuildBatch(client, builder.BuildBatchParams{
		Account: senderAddress,
		Operations: []builder.BatchOperation{
			sendOperation(senderAddress, receiverAddress, issuanceID, senderKey, batchFirstSend),
			sendOperation(senderAddress, receiverAddress, issuanceID, senderKey, batchSecondSend),
			builder.MergeInboxOp{BuildMergeInboxParams: builder.BuildMergeInboxParams{
				Account:    receiverAddress,
				IssuanceID: issuanceID,
			}},
			sendOperation(receiverAddress, senderAddress, issuanceID, receiverKey, batchReturnSend),
		},
	})
	require.NoError(t, err)
	require.Len(t, batch.RawTransactions, 4)
	require.Equal(t, transaction.TfAllOrNothing, batch.Flags)

	// Each account's inners take consecutive sequences, and the Batch account's start one
	// past the sequence the Batch itself spends.
	require.Equal(t, batch.Sequence+1, innerSequence(t, batch, 0))
	require.Equal(t, batch.Sequence+2, innerSequence(t, batch, 1))
	require.Equal(t, innerSequence(t, batch, 2)+1, innerSequence(t, batch, 3))

	response := submitBatch(t, runner, client, batch, sender, receiver)
	t.Logf("validated Batch %s in ledger %d with %s", response.Hash, response.LedgerIndex, response.Meta.TransactionResult)

	// The sender spent twice and received once. A received amount lands in the inbox, so it
	// is not in the spending balance until a merge moves it, and only the two sends advanced
	// the sender's version.
	const senderSpending = batchSenderFunding - batchFirstSend - batchSecondSend
	assertSplitBalances(t, client, sender.GetAddress(), senderKey.PrivKeyHex, batchReturnSend, senderSpending, 3)
	assertMirrorBalances(t, client, sender.GetAddress(), config, senderSpending+batchReturnSend)

	// The receiver merged both credits into its spending balance and then spent from it. The
	// merge and the send each advanced its version; the two incoming sends did not, because
	// a credit to the inbox leaves the spending balance a proof binds untouched.
	const receiverSpending = batchReceiverFunding + batchFirstSend + batchSecondSend - batchReturnSend
	assertSplitBalances(t, client, receiver.GetAddress(), receiverKey.PrivKeyHex, 0, receiverSpending, 3)
	assertMirrorBalances(t, client, receiver.GetAddress(), config, receiverSpending)

	// A send moves value between holders without creating or destroying any, so the
	// confidential supply is exactly what the two converts put into it.
	issuance := getIssuance(t, client, issuer.GetAddress())
	require.Equal(t, batchSenderFunding+batchReceiverFunding, parseMPTAmount(t, issuance.ConfidentialOutstandingAmount))
	require.Equal(t, senderSpending+batchReturnSend+receiverSpending, parseMPTAmount(t, issuance.ConfidentialOutstandingAmount))
}

// sendOperation builds one send inner of the dependent batch.
func sendOperation(from, to, issuanceID string, key elgamal.Keypair, amount uint64) builder.SendOp {
	return builder.SendOp{BuildSendParams: builder.BuildSendParams{
		Account:       from,
		Destination:   to,
		IssuanceID:    issuanceID,
		Amount:        amount,
		SenderPrivKey: key.PrivKeyHex,
		SenderPubKey:  key.PubKeyHex,
		BalanceRange:  batchSearchRange(),
	}}
}

// convertAndMerge gives a holder a spendable confidential balance, which is the starting
// state every inner of the dependent batch assumes.
func convertAndMerge(
	t *testing.T,
	runner *integration.Runner,
	client confidentialClient,
	holder *wallet.Wallet,
	issuanceID string,
	key elgamal.Keypair,
	amount uint64,
) {
	t.Helper()

	convert, err := builder.BuildConvert(client, builder.BuildConvertParams{
		Account:       holder.GetAddress().String(),
		IssuanceID:    issuanceID,
		Amount:        amount,
		HolderPrivKey: key.PrivKeyHex,
		HolderPubKey:  key.PubKeyHex,
	})
	require.NoError(t, err)
	submitAndWait(t, runner, convert.Flatten(), holder)

	merge, err := builder.BuildMergeInbox(client, builder.BuildMergeInboxParams{
		Account:    holder.GetAddress().String(),
		IssuanceID: issuanceID,
	})
	require.NoError(t, err)
	submitAndWait(t, runner, merge.Flatten(), holder)
}

// submitBatch autofills, signs, and submits an assembled Batch, and waits for validation.
// The assembler leaves signing to the caller: every account other than the outer one signs
// the Batch with SignMultiBatch, and the outer account signs the Batch itself.
//
// Autofill runs over the assembled Batch on purpose. It prices the outer fee by summing the
// inners, charging each confidential inner the multiplier rippled applies, and it cannot
// disturb a proof: the assembler already set every nonce a proof binds, and autofill assigns
// only the ones that are missing.
func submitBatch(
	t *testing.T,
	runner *integration.Runner,
	client confidentialClient,
	batch *transaction.Batch,
	outer *wallet.Wallet,
	coSigner *wallet.Wallet,
) *transactions.TxResponse {
	t.Helper()

	flat := batch.Flatten()
	require.NoError(t, client.AutofillMultisigned(&flat, 1))
	require.NoError(t, wallet.SignMultiBatch(*coSigner, &flat, nil))

	response, err := runner.TestSuccessfulTransactionAndWait(&flat, outer, &integration.TestTransactionOptions{SkipAutofill: true})
	require.NoError(t, err)
	return response
}

// innerSequence reads the sequence the assembler assigned to one inner.
func innerSequence(t *testing.T, batch *transaction.Batch, index int) uint32 {
	t.Helper()

	require.Greater(t, len(batch.RawTransactions), index)
	sequence, ok := batch.RawTransactions[index].RawTransaction["Sequence"].(uint32)
	require.True(t, ok, "inner %d must carry a Sequence", index)
	return sequence
}

// TestIntegrationConfidentialMPTDependentBatch_Websocket runs the dependent batch over the
// WebSocket client.
func TestIntegrationConfidentialMPTDependentBatch_Websocket(t *testing.T) {
	env := integration.GetWebsocketEnv(t)
	client := websocket.NewClient(websocket.NewClientConfig().WithHost(env.Host).WithFaucetProvider(env.FaucetProvider))
	testIntegrationConfidentialMPTDependentBatch(t, client)
}

// TestIntegrationConfidentialMPTDependentBatch_RPCClient runs the dependent batch over the
// JSON-RPC client.
func TestIntegrationConfidentialMPTDependentBatch_RPCClient(t *testing.T) {
	env := integration.GetRPCEnv(t)
	clientCfg, err := rpc.NewClientConfig(env.Host, rpc.WithFaucetProvider(env.FaucetProvider))
	require.NoError(t, err)
	client := rpc.NewClient(clientCfg)
	testIntegrationConfidentialMPTDependentBatch(t, client)
}
