// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import {ModuleManager} from "lib/safe-smart-account/contracts/base/ModuleManager.sol";
import {Enum} from "lib/safe-smart-account/contracts/common/Enum.sol";
import {ISafeTx} from "../common/ISafeTx.sol";
import {SiglessTransactionExecutor} from "../libraries/SiglessTransactionExecutor.sol";

interface ISafe {
    // thing reverts if the signatures are invalid
    function checkSignatures(bytes32 dataHash, bytes memory data, bytes memory signatures) external view;
}

/**
 * @title MultiChainSignaturesModule - An extension to the Safe contract that allows to execute transactions on multiple chains in one signature.
 * @dev The contract verifies signatures in a similar fashion to the Safe contract (in fact, most code was forked from the Safe contract),
 *      but it (TBF, against the EIP-712 specs) hardcodes the chain ID to 1 instead of using the real chain ID.
 *      This allows to use a single signature (or a set of signatures) to execute a transaction on multiple instances of the same multisig.
 *      Security considerations:
 *      - The module is limited to delegatecalling MultiSendWithChainFilter, which requires specifying the chain ID for each operation.
          Operations that have a different chain ID specified are skipped (not executed) on the specific instance.
          This way, we avoid the risk of replay attacks, while implementing as few code on top of Safe's stack as possible.
 * @custom:security-contact contact@ultrasoundlabs.org
 */
contract MultiChainSignaturesModule is ISafeTx {

    struct SafeTxBatch {
        SafeTx[] safeTxs;
        uint256[] chainIds;
    }

    // The version of the contract
    string public constant VERSION = "1.5.0-MCSM";

    // keccak256(
    //     "EIP712Domain(uint256 chainId,address verifyingContract)"
    // );
    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    // keccak256(
    //     "SafeTxBatch(SafeTx[] safeTxs,uint256[] chainIds)SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
    // );
    bytes32 private constant SAFE_TX_BATCH_TYPEHASH = 0x380edc5493295a56ffff58d3918c1c94a127a863c855db293ab15a2b63f05922;

    // keccak256(
    //     "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
    // );
    bytes32 private constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    // The address of the SiglessTransactionExecutor contract
    address public immutable SIGLESS_TRANSACTION_EXECUTOR;

    // The constructor
    constructor(address _siglessTransactionExecutor) {
        SIGLESS_TRANSACTION_EXECUTOR = _siglessTransactionExecutor;
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, 1 /* Ethereum L1's chainId */, this));
    }

    /**
     * @notice Returns the pre-image of the transaction batch hash (see Safe.getTransactionHash for reference).
     * @dev This function encodes the batch of SafeTx structs and the array of chainIds into a single EIP-712 preimage.
     *      This is used for signature verification for the batch.
     * @param safeTxBatch The batch of SafeTx structs and chainIds.
     * @return The EIP-712 preimage for the batch transaction.
     * @dev Forked from Safe.encodeTransactionData.
     */
    function encodeTransactionBatchData(
        SafeTxBatch calldata safeTxBatch
    ) public view returns (bytes memory) {
        // First, encode each SafeTx in the batch using the same struct hashing as Safe.
        bytes32[] memory safeTxHashes = new bytes32[](safeTxBatch.safeTxs.length);
        for (uint256 i = 0; i < safeTxBatch.safeTxs.length; i++) {
            SafeTx calldata tx_ = safeTxBatch.safeTxs[i];
            safeTxHashes[i] = keccak256(
                abi.encode(
                    SAFE_TX_TYPEHASH,
                    tx_.to,
                    tx_.value,
                    keccak256(tx_.data),
                    tx_.operation,
                    tx_.safeTxGas,
                    tx_.baseGas,
                    tx_.gasPrice,
                    tx_.gasToken,
                    tx_.refundReceiver,
                    tx_.nonce
                )
            );
        }

        // Hash the array of SafeTx hashes
        bytes32 safeTxsHash = keccak256(abi.encodePacked(safeTxHashes));

        // Hash the array of chainIds
        bytes32 chainIdsHash = keccak256(abi.encodePacked(safeTxBatch.chainIds));

        // Now, hash the batch struct
        bytes32 batchHash = keccak256(
            abi.encode(
                SAFE_TX_BATCH_TYPEHASH,
                safeTxsHash,
                chainIdsHash
            )
        );

        // Return the EIP-712 preimage for the batch
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), batchHash);
    }

    function execTransactionBatch(
        address account,
        SafeTxBatch calldata safeTxBatch,
        bytes calldata signatures
    ) public returns (bool) {
        bytes memory encodedData = encodeTransactionBatchData(safeTxBatch);
        ISafe(account).checkSignatures(
            keccak256(encodedData),
            encodedData,
            signatures
        ); // reverts if the signatures are invalid

        uint256 failedTxs = 0;
        for (uint256 i = 0; i < safeTxBatch.safeTxs.length; i++) {
            if (safeTxBatch.chainIds[i] != block.chainid) continue;

            if (!ModuleManager(account).execTransactionFromModule(
                SIGLESS_TRANSACTION_EXECUTOR,
                0,
                abi.encodeWithSelector(SiglessTransactionExecutor.execTransaction.selector, safeTxBatch.safeTxs[i]),
                Enum.Operation.DelegateCall
            )) failedTxs++;
        }

        return failedTxs == 0;
    }
}