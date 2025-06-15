// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

/**
 * @title Multi Send With Chain Filter - Allows to batch multiple transactions into one, but skips transactions with chain ID not equal to the current chain ID
 * @notice The guard logic is not required here as this contract doesn't support nested delegate calls
 * @author Ultrasound Labs - @ultrasoundlabs
 * @dev Forked from Safe's MultiSendCallOnly.sol by @Georgi87 and @rmeissner
 */
contract MultiSendWithChainFilter {
    /**
     * @dev Sends multiple transactions and reverts all if one fails.
     * @param transactions Encoded transactions. Each transaction is encoded as a packed bytes of
     *                     chain ID as a uint256 (=> 32 bytes),
     *                     operation has to be uint8(0) in this version (=> 1 byte),
     *                     to as a address (=> 20 bytes),
     *                     value as a uint256 (=> 32 bytes),
     *                     data length as a uint256 (=> 32 bytes),
     *                     data as bytes.
     *                     see abi.encodePacked for more information on packed encoding
     * @notice The code is for the most part the same as MultiSendCallOnly (MultiSend with delegatecall protection)
     *         but skips transactions with chain ID not equal to the current chain ID
     */
    function multiSend(bytes memory transactions) public payable {
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            let length := mload(transactions)
            let i := 0x20
            // Explanation:
            // Since the chainId is now the first 32 bytes of each transaction struct,
            // all subsequent field offsets must be increased by 32 bytes (0x20).
            // The new layout for each transaction is:
            // [0x00..0x20)  chainId (32 bytes)
            // [0x20)        operation (1 byte)
            // [0x21..0x35)  to (20 bytes)
            // [0x35..0x55)  value (32 bytes)
            // [0x55..0x75)  dataLength (32 bytes)
            // [0x75..0x75+dataLength) data (dataLength bytes)

            for {
                // Pre block is not used in "while mode"
            } lt(i, length) {
                // Post block is not used in "while mode"
            } {
                // First 32 bytes of the data is the chain ID
                let chainId := mload(add(transactions, i))
                if iszero(eq(chainId, chainid())) {
                    // If chainId doesn't match, skip to the next transaction.
                    // But to skip, we need to know the full length of this transaction.
                    // So, read dataLength at the correct offset.
                    let dataLength := mload(add(transactions, add(i, 0x55)))
                    // Move i to the start of the next transaction
                    i := add(i, add(0x75, dataLength))
                    continue
                }
                // If the chain ID is equal to the current chain ID, process the transaction
                // Operation is at offset 0x20 (32 bytes after i)
                let operation := shr(0xf8, mload(add(transactions, add(i, 0x20))))
                // To address is at offset 0x21 (32 + 1)
                let to := shr(0x60, mload(add(transactions, add(i, 0x21))))
                // Defaults `to` to `address(this)` if `address(0)` is provided.
                to := or(to, mul(iszero(to), address()))
                // Value is at offset 0x35 (32 + 1 + 20)
                let value := mload(add(transactions, add(i, 0x35)))
                // Data length is at offset 0x55 (32 + 1 + 20 + 32)
                let dataLength := mload(add(transactions, add(i, 0x55)))
                // Data is at offset 0x75 (32 + 1 + 20 + 32 + 32)
                let data := add(transactions, add(i, 0x75))
                let success := 0
                switch operation
                case 0 {
                    success := call(gas(), to, value, data, dataLength, 0, 0)
                }
                // This version does not allow delegatecalls
                case 1 {
                    revert(0, 0)
                }
                if iszero(success) {
                    let ptr := mload(0x40)
                    returndatacopy(ptr, 0, returndatasize())
                    revert(ptr, returndatasize())
                }
                // Next entry starts at 0x75 + dataLength
                i := add(i, add(0x75, dataLength))
            }
        }
        /* solhint-enable no-inline-assembly */
    }
}