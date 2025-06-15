// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console, Vm} from "forge-std/Test.sol";
import {Safe} from "lib/safe-smart-account/contracts/Safe.sol";
import {ISafeTx} from "src/common/ISafeTx.sol";
import {MultiChainSignaturesModule} from "src/modules/MultiChainSignaturesModule.sol";
import {SiglessTransactionExecutor} from "src/libraries/SiglessTransactionExecutor.sol";
import {Enum} from "lib/safe-smart-account/contracts/common/Enum.sol";
import {SafeProxyFactory} from "lib/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "lib/safe-smart-account/contracts/proxies/SafeProxy.sol";

// A simple target contract for our tests to call.
// It has a function that changes its state and can receive Ether,
// allowing us to easily check if a transaction was successful.
contract Target {
    bool public executed;
    uint256 public value;

    function executeWithValue() public payable {
        executed = true;
        value = msg.value;
    }

    function someOtherFunction() public {
        // another function to call
    }
}

// A helper contract that always reverts. Used to simulate failing SafeTx executions.
contract RevertTarget {
    function willRevert() external pure {
        revert("INTENTIONAL_REVERT");
    }
}

contract MultiChainSignaturesModuleTest is Test, ISafeTx {
    // === State Variables ===
    Safe internal safe;
    MultiChainSignaturesModule internal module;
    SiglessTransactionExecutor internal executor;
    Target internal target;
    RevertTarget internal revertTarget;

    // Wallet for the owner of the Safe. We use a known private key
    // so we can sign messages with it.
    uint256 internal constant OWNER_PK = 0x12345;
    address internal owner;

    /**
     * @notice This function is run before each test. It sets up a complete,
     * integrated environment with a Safe, the module, and the executor.
     */
    function setUp() public {
        // 1. Create a wallet for the Safe owner
        owner = vm.addr(OWNER_PK);

        // 2. Deploy the Safe via a proxy to mimic real-world usage.
        //    First deploy the singleton (implementation) and the proxy factory.
        Safe singleton = new Safe();
        SafeProxyFactory proxyFactory = new SafeProxyFactory();

        // 3. Prepare the initializer payload for the proxy creation (encodes a call to Safe.setup).
        address[] memory owners = new address[](1);
        owners[0] = owner;
        bytes memory initializer = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            uint256(1),
            address(0),
            bytes(""),
            address(0),
            address(0),
            uint256(0),
            payable(address(0))
        );

        // 4. Deploy the proxy Safe and cast it back to the Safe interface.
        SafeProxy proxy = proxyFactory.createProxyWithNonce(address(singleton), initializer, 0);
        safe = Safe(payable(address(proxy)));

        // Fund the safe with some ETH for tests that involve sending value.
        vm.deal(address(safe), 10 ether);

        // 5. Deploy the contracts from your project.
        executor = new SiglessTransactionExecutor();
        // The module needs to know the address of the executor.
        module = new MultiChainSignaturesModule(address(executor));

        // 6. Deploy our simple target contract.
        target = new Target();

        //    Deploy a contract that will intentionally revert.
        revertTarget = new RevertTarget();

        // 7. Enable the MultiChainSignaturesModule on the Safe.
        // This is a privileged action that only owners can perform.
        // We use `vm.prank` to simulate the owner calling this function.
        vm.prank(address(safe));
        safe.enableModule(address(module));
        assertTrue(safe.isModuleEnabled(address(module)), "Module should be enabled");
    }

    /*//////////////////////////////////////////////////////////////
                           HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice A helper function to sign a SafeTxBatch.
     * @dev It calculates the EIP-712 hash the same way the module does
     *      and then signs it using the owner's private key.
     * @param batch The batch of transactions to sign.
     * @return signatures A packed byte array of the r, s, and v values of the signature.
     */
    function _signBatch(MultiChainSignaturesModule.SafeTxBatch memory batch) internal returns (bytes memory) {
        bytes32 dataHash = keccak256(module.encodeTransactionBatchData(batch));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, dataHash);
        return abi.encodePacked(r, s, v);
    }

    /*//////////////////////////////////////////////////////////////
                                TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test the primary success case: a valid batch with valid signatures
     *         is executed correctly. One transaction is for the current chain,
     *         and the other is for a different chain (and should be skipped).
     */
    function test_Success_ExecBatch_OneTxForThisChain() public {
        // ARRANGE: Create a batch with one tx for the current chain
        // and one for another chain.
        SafeTx[] memory txs = new SafeTx[](2);
        uint256[] memory chainIds = new uint256[](2);

        // Transaction 1: Meant for our chain (Foundry's Anvil runs on chainid 31337).
        // It will call `executeWithValue` on the Target contract and send 1 ether.
        txs[0] = SafeTx({
            to: address(target),
            value: 1 ether,
            data: abi.encodeWithSelector(Target.executeWithValue.selector),
            operation: uint8(Enum.Operation.Call),
            safeTxGas: 100000,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            nonce: safe.nonce() // The nonce must match the Safe's current nonce.
        });
        chainIds[0] = block.chainid;

        // Transaction 2: Meant for another chain (e.g., Ethereum Mainnet, chainid 1).
        // This transaction should be ignored by the module during execution.
        txs[1] = SafeTx({
            to: address(target),
            value: 0,
            data: abi.encodeWithSelector(Target.someOtherFunction.selector),
            operation: uint8(Enum.Operation.Call),
            safeTxGas: 100000,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            nonce: safe.nonce() // Nonce is part of signed data, must be included.
        });
        chainIds[1] = 1;

        MultiChainSignaturesModule.SafeTxBatch memory batch = MultiChainSignaturesModule.SafeTxBatch(txs, chainIds);

        // Sign the batch with the owner's key.
        bytes memory signatures = _signBatch(batch);

        // ACT: Execute the transaction batch via the module.
        // We expect two events: one from the ModuleManager and one from the SiglessTransactionExecutor.
        vm.recordLogs();
        bool success = module.execTransactionBatch(address(safe), batch, signatures);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // ASSERT: Check that everything happened as expected.
        assertTrue(success, "execTransactionBatch should return true");

        // Check that the target contract was called correctly.
        assertTrue(target.executed(), "Target contract should have been executed");
        assertEq(target.value(), 1 ether, "Target should have received 1 ether");

        // Check that the Safe's nonce has increased by 1 for the executed transaction.
        assertEq(safe.nonce(), 1, "Safe nonce should be incremented");

        // Check that the Safe's balance has decreased by the value sent.
        assertEq(address(safe).balance, 9 ether, "Safe balance should be lower by 1 ether");

        // Check for the correct events
        assertEq(logs.length, 2, "Should have emitted two events");
        // Event 1: From SiglessTransactionExecutor
        assertEq(logs[0].topics[0], keccak256("ExecutionSuccess(bytes32,uint256)"));
        // Event 2: From ModuleManager (on Safe)
        assertEq(logs[1].topics[0], keccak256("ExecutionFromModuleSuccess(address)"));
        assertEq(address(uint160(uint256(logs[1].topics[1]))), address(module));
    }

    /**
     * @notice Test the security of the module: a batch signed by an unauthorized
     *         wallet should be rejected.
     */
    function test_Revert_ExecBatch_InvalidSignature() public {
        // ARRANGE: Create a batch and sign it with an unauthorized key.
        SafeTx[] memory txs = new SafeTx[](1);
        uint256[] memory chainIds = new uint256[](1);
        txs[0] = SafeTx({
            to: address(target),
            value: 0,
            data: "",
            operation: uint8(Enum.Operation.Call),
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            nonce: safe.nonce()
        });
        chainIds[0] = block.chainid;
        MultiChainSignaturesModule.SafeTxBatch memory batch = MultiChainSignaturesModule.SafeTxBatch(txs, chainIds);

        // Sign with a random, non-owner private key.
        uint256 randomPk = 0xBAD516;
        bytes32 dataHash = keccak256(module.encodeTransactionBatchData(batch));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(randomPk, dataHash);
        bytes memory badSignatures = abi.encodePacked(r, s, v);

        // ASSERT: Expect the call to revert. The Safe's `checkSignatures`
        // function reverts with "GS026" for invalid signatures. The module's
        // call will bubble up this revert.
        vm.expectRevert("GS026");

        // ACT: Attempt to execute with the bad signature.
        module.execTransactionBatch(address(safe), batch, badSignatures);
    }

    /**
     * @notice Test the filtering logic: if a batch contains no transactions for
     *         the current chain, it should execute successfully but do nothing.
     */
    function test_Success_ExecBatch_NoTxsForThisChain() public {
        // ARRANGE: Create a batch where all txs are for other chains.
        SafeTx[] memory txs = new SafeTx[](1);
        uint256[] memory chainIds = new uint256[](1);
        txs[0] = SafeTx({
            to: address(target),
            value: 0,
            data: "",
            operation: uint8(Enum.Operation.Call),
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            nonce: safe.nonce()
        });
        chainIds[0] = 999; // Some other chain ID, not the current one.
        MultiChainSignaturesModule.SafeTxBatch memory batch = MultiChainSignaturesModule.SafeTxBatch(txs, chainIds);

        bytes memory signatures = _signBatch(batch);

        // ACT: Execute the batch.
        // No transactions are for this chain, so no events are expected. We simply
        // don't set an expectEmit, and the test will proceed.
        bool success = module.execTransactionBatch(address(safe), batch, signatures);

        // ASSERT: The call should succeed, but no state should have changed.
        assertTrue(success, "execTransactionBatch should return true even if no txs are executed");

        // Check that the target contract was NOT called.
        assertFalse(target.executed(), "Target should not have been executed");
        // Check that the Safe's nonce did NOT change.
        assertEq(safe.nonce(), 0, "Safe nonce should NOT be incremented");
        // Check that the Safe's balance is unchanged.
        assertEq(address(safe).balance, 10 ether, "Safe balance should be unchanged");
    }

    /**
     * @notice Execute a batch that contains two transactions, both for the current
     *         chain. Both should succeed and the module should return true.
     */
    function test_Success_ExecBatch_TwoTxs_CurrentChain() public {
        // ARRANGE
        SafeTx[] memory txs = new SafeTx[](2);
        uint256[] memory chainIds = new uint256[](2);

        // First tx – send 0.5 ether to target
        txs[0] = SafeTx({
            to: address(target),
            value: 0.5 ether,
            data: abi.encodeWithSelector(Target.executeWithValue.selector),
            operation: uint8(Enum.Operation.Call),
            safeTxGas: 100000,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            nonce: safe.nonce()
        });
        chainIds[0] = block.chainid;

        // Second tx – call someOtherFunction with no value
        txs[1] = SafeTx({
            to: address(target),
            value: 0,
            data: abi.encodeWithSelector(Target.someOtherFunction.selector),
            operation: uint8(Enum.Operation.Call),
            safeTxGas: 100000,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            nonce: safe.nonce() + 1
        });
        chainIds[1] = block.chainid;

        MultiChainSignaturesModule.SafeTxBatch memory batch = MultiChainSignaturesModule.SafeTxBatch(txs, chainIds);
        bytes memory sigs = _signBatch(batch);

        // ACT
        vm.recordLogs();
        bool success = module.execTransactionBatch(address(safe), batch, sigs);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // ASSERT
        assertTrue(success, "Batch should succeed");
        assertEq(safe.nonce(), 2, "Nonce should advance by 2");
        assertEq(address(safe).balance, 9.5 ether, "Safe balance should drop by 0.5 ether");
        assertTrue(target.executed(), "executeWithValue should have run");

        // Check for four success events (2 from executor, 2 from module manager)
        assertEq(logs.length, 4, "Should have emitted four events");
        assertEq(logs[0].topics[0], keccak256("ExecutionSuccess(bytes32,uint256)"));
        assertEq(logs[1].topics[0], keccak256("ExecutionFromModuleSuccess(address)"));
        assertEq(address(uint160(uint256(logs[1].topics[1]))), address(module));
        assertEq(logs[2].topics[0], keccak256("ExecutionSuccess(bytes32,uint256)"));
        assertEq(logs[3].topics[0], keccak256("ExecutionFromModuleSuccess(address)"));
        assertEq(address(uint160(uint256(logs[3].topics[1]))), address(module));
    }

    /**
     * @notice Provide a batch that uses an incorrect nonce. Execution should
     *         fail (module returns false) and no state must be changed.
     */
    function test_Failure_ExecBatch_WrongNonce() public {
        // ARRANGE – give nonce that is one ahead of expected
        SafeTx[] memory txs = new SafeTx[](1);
        uint256[] memory chainIds = new uint256[](1);
        txs[0] = SafeTx({
            to: address(target),
            value: 0,
            data: "",
            operation: uint8(Enum.Operation.Call),
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            nonce: safe.nonce() + 1 // WRONG!
        });
        chainIds[0] = block.chainid;

        MultiChainSignaturesModule.SafeTxBatch memory batch = MultiChainSignaturesModule.SafeTxBatch(txs, chainIds);
        bytes memory sigs = _signBatch(batch);

        // ACT
        bool success = module.execTransactionBatch(address(safe), batch, sigs);

        // ASSERT – execution should report failure and leave state untouched
        assertFalse(success, "Batch should report failure");
        assertEq(safe.nonce(), 0, "Nonce must not change");
        assertFalse(target.executed(), "Target should not be executed");
    }

    /**
     * @notice Mixed batch: first tx succeeds, second one reverts inside the
     *         called contract. Module should return false but keep effects
     *         of the successful tx.
     */
    function test_Failure_ExecBatch_PartialSuccess() public {
        // ARRANGE
        SafeTx[] memory txs = new SafeTx[](2);
        uint256[] memory chainIds = new uint256[](2);

        // Tx 0 – will succeed
        txs[0] = SafeTx({
            to: address(target),
            value: 0,
            data: abi.encodeWithSelector(Target.executeWithValue.selector),
            operation: uint8(Enum.Operation.Call),
            safeTxGas: 100000,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            nonce: safe.nonce()
        });
        chainIds[0] = block.chainid;

        // Tx 1 – will revert
        txs[1] = SafeTx({
            to: address(revertTarget),
            value: 0,
            data: abi.encodeWithSelector(RevertTarget.willRevert.selector),
            operation: uint8(Enum.Operation.Call),
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            nonce: safe.nonce() + 1
        });
        chainIds[1] = block.chainid;

        MultiChainSignaturesModule.SafeTxBatch memory batch = MultiChainSignaturesModule.SafeTxBatch(txs, chainIds);
        bytes memory sigs = _signBatch(batch);

        // ACT
        vm.recordLogs();
        bool success = module.execTransactionBatch(address(safe), batch, sigs);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // ASSERT
        assertFalse(success, "Batch should report failure due to second tx");
        assertEq(safe.nonce(), 1, "Nonce should increment only for first successful tx");
        assertTrue(target.executed(), "First tx should have executed");

        // Check for the events from the single successful transaction.
        // The failing transaction may or may not emit events depending on the nature of the failure,
        // so we don't assert on its events for a more robust test.
        assertTrue(logs.length >= 2, "Should have at least emitted events for the successful tx");
        // Tx 1 (Success)
        assertEq(logs[0].topics[0], keccak256("ExecutionSuccess(bytes32,uint256)"));
        assertEq(logs[1].topics[0], keccak256("ExecutionFromModuleSuccess(address)"));
        assertEq(address(uint160(uint256(logs[1].topics[1]))), address(module));
    }

    /**
     * @notice Test replay protection: executing the same batch twice should fail
     *         the second time due to the nonce being used.
     */
    function test_Failure_ExecBatch_ReplayOnSameChain() public {
        // ARRANGE: Create and execute a valid batch once.
        SafeTx[] memory txs = new SafeTx[](1);
        uint256[] memory chainIds = new uint256[](1);
        txs[0] = SafeTx({
            to: address(target),
            value: 1 ether,
            data: abi.encodeWithSelector(Target.executeWithValue.selector),
            operation: uint8(Enum.Operation.Call),
            safeTxGas: 100000,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            nonce: safe.nonce()
        });
        chainIds[0] = block.chainid;
        MultiChainSignaturesModule.SafeTxBatch memory batch = MultiChainSignaturesModule.SafeTxBatch(txs, chainIds);
        bytes memory signatures = _signBatch(batch);

        // ACT 1: First execution should succeed.
        bool firstSuccess = module.execTransactionBatch(address(safe), batch, signatures);
        assertTrue(firstSuccess, "First execution should succeed");
        assertEq(safe.nonce(), 1, "Nonce should be 1 after first execution");

        // ACT 2: Attempt to execute the exact same batch again.
        // This must fail because the nonce (0) is now invalid.
        bool secondSuccess = module.execTransactionBatch(address(safe), batch, signatures);

        // ASSERT
        assertFalse(secondSuccess, "Second execution should fail due to nonce reuse");
        assertEq(safe.nonce(), 1, "Nonce should remain 1");
    }
}
