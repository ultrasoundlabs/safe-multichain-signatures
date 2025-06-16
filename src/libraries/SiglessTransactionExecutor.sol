// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import {ISafeTx} from "../common/ISafeTx.sol";
import {SafeMath} from "lib/safe-smart-account/contracts/external/SafeMath.sol";
import {Guard} from "lib/safe-smart-account/contracts/base/GuardManager.sol";
import {Enum} from "lib/safe-smart-account/contracts/common/Enum.sol";
import {Safe} from "lib/safe-smart-account/contracts/Safe.sol";

// import {ITransactionGuard, GuardManager} from "lib/safe-smart-account/contracts/base/GuardManager.sol";

/**
 * @title Sigless Transaction Executor - Allows to execute transactions without a signature
 * @notice Safe account has to delegatecall this contract to execute SafeTx with a normal flow except for the signature verification
 * @author Ultrasound Labs - @ultrasoundlabs
 *
 * This contract merges the "sigless" execution (no signature check) with the full Safe transaction execution logic.
 * It allows you to execute a SafeTx struct directly, skipping signature checks, but still performing all the other
 * steps (gas accounting, payment, etc) as in the original Safe contract.
 */
contract SiglessTransactionExecutor is ISafeTx, Safe {
    using SafeMath for uint256;

    /**
     * @notice Function which uses assembly to revert with the passed error message.
     * @param error The error string to revert with.
     * @dev Currently it is expected that the `error` string is at max 5 bytes of length. Ex: "GSXXX"
     */
    function revertWithError(bytes5 error) internal pure {
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x08c379a000000000000000000000000000000000000000000000000000000000) // Selector for method "Error(string)"
            mstore(add(ptr, 0x04), 0x20) // String offset
            mstore(add(ptr, 0x24), 0x05) // Revert reason length (5 bytes for bytes5)
            mstore(add(ptr, 0x44), error) // Revert reason
            revert(ptr, 0x64) // Revert data length is 4 bytes for selector + offset + error length + error.
        }
        /* solhint-enable no-inline-assembly */
    }

    /**
     * @notice Execute a SafeTx without requiring a signature.
     * @dev This function unpacks the SafeTx struct and executes the transaction using the same logic as the original Safe contract,
     *      but skips signature verification. This is useful for trusted modules or scenarios where signature checks are not needed.
     * @param safeTx The SafeTx struct containing all transaction parameters.
     * @return success True if the transaction was executed successfully, false otherwise.
     */
    function execTransaction(SafeTx calldata safeTx) public returns (bool success) {
        // Unpack the SafeTx struct fields for clarity and easier use.
        address to = safeTx.to;
        uint256 value = safeTx.value;
        bytes memory data = safeTx.data;
        uint8 operation = safeTx.operation;
        uint256 safeTxGas = safeTx.safeTxGas;
        uint256 baseGas = safeTx.baseGas;
        uint256 gasPrice = safeTx.gasPrice;
        address gasToken = safeTx.gasToken;
        address payable refundReceiver = payable(safeTx.refundReceiver);
        uint256 _nonce = safeTx.nonce;

        // Before execution, call the guard hook if present.
        address guard = getGuard();
        if (guard != address(0)) {
            Guard(guard).checkTransaction(
                to,
                value,
                data,
                Enum.Operation(operation),
                safeTxGas,
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver,
                // No signatures, so pass empty bytes
                "",
                msg.sender
            );
        }

        // The signature was already verified in the multi-chain signature module, so we don't need to do it here.
        // However, that module did not verify the nonce, so we need to do it here.
        // GS024 is "Invalid signature" because nonce validation is a part of the signature verification, even though done in a different module.
        // We increment the nonce in a similar way to how the Safe contract constructs data to verify the signature against.
        if (_nonce != nonce++) revertWithError("GS024");

        // We require some gas to emit the events (at least 2500) after the execution and some to perform code until the execution (500)
        // We also include the 1/64 in the check that is not sent along with a call to counteract potential shortings because of EIP-150
        // We use `<< 6` instead of `* 64` as SHR / SHL opcode only uses 3 gas, while DIV / MUL opcode uses 5 gas.
        if (gasleft() < ((safeTxGas << 6) / 63 > safeTxGas + 2500 ? (safeTxGas << 6) / 63 : safeTxGas + 2500) + 500) {
            revertWithError("GS010");
        }

        // Use a scope to limit variable lifetime and prevent "stack too deep" errors
        {
            uint256 gasUsed = gasleft();
            // If the gasPrice is 0 we assume that nearly all available gas can be used (it is always more than safeTxGas)
            // We only subtract 2500 (compared to the 3000 before) to ensure that the amount passed is still higher than safeTxGas
            success =
                execute(to, value, data, Enum.Operation(operation), gasPrice == 0 ? (gasleft() - 2500) : safeTxGas);
            gasUsed = gasUsed - gasleft();
            // If no safeTxGas and no gasPrice was set (e.g. both are 0), then the internal tx is required to be successful
            // This makes it possible to use `estimateGas` without issues, as it searches for the minimum gas where the tx doesn't revert
            if (!success && safeTxGas == 0 && gasPrice == 0) {
                /* solhint-disable no-inline-assembly */
                /// @solidity memory-safe-assembly
                assembly {
                    let ptr := mload(0x40)
                    returndatacopy(ptr, 0, returndatasize())
                    revert(ptr, returndatasize())
                }
                /* solhint-enable no-inline-assembly */
            }
            // We transfer the calculated tx costs to the tx.origin to avoid sending it to intermediate contracts that have made calls
            uint256 payment = 0;
            if (gasPrice > 0) {
                payment = _handlePayment(gasUsed, baseGas, gasPrice, gasToken, refundReceiver);
            }
            // For demonstration, we emit events as in the original Safe contract.
            if (success) emit ExecutionSuccess(bytes32(0), payment); // No txHash, as we skip signature logic

            else emit ExecutionFailure(bytes32(0), payment);
        }

        // After execution, call the guard hook if present.
        if (guard != address(0)) {
            Guard(guard).checkAfterExecution(bytes32(0), success);
        }
    }

    /**
     * @notice Handles the payment for a Safe transaction.
     * @param gasUsed Gas used by the Safe transaction.
     * @param baseGas Gas costs that are independent of the transaction execution (e.g. base transaction fee, signature check, payment of the refund).
     * @param gasPrice Gas price that should be used for the payment calculation.
     * @param gasToken Token address (or 0 if ETH) that is used for the payment.
     * @return payment The amount of payment made in the specified token.
     * @dev Forked from Safe.sol because there this function is private for some reason.
     */
    function _handlePayment(
        uint256 gasUsed,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver
    ) private returns (uint256 payment) {
        // solhint-disable-next-line avoid-tx-origin
        address payable receiver = refundReceiver == address(0) ? payable(tx.origin) : refundReceiver;
        if (gasToken == address(0)) {
            // For ETH we will only adjust the gas price to not be higher than the actual used gas price
            payment = gasUsed.add(baseGas).mul(gasPrice < tx.gasprice ? gasPrice : tx.gasprice);
            if (!receiver.send(payment)) revertWithError("GS011");
        } else {
            payment = gasUsed.add(baseGas).mul(gasPrice);
            if (!transferToken(gasToken, receiver, payment)) revertWithError("GS012");
        }
    }
}
