// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {CreateXScript} from "createx-forge/script/CreateXScript.sol";
import {SiglessTransactionExecutor} from "../src/libraries/SiglessTransactionExecutor.sol";

/// @title SiglessTransactionExecutor deterministic deployer
/// @notice Anyone can run this script on any EVM network and obtain the exact
///         same contract address (provided the byte-code and salt stay the same).
///         We use the universal CreateX factory together with the CREATE2 opcode.
contract SiglessTransactionExecutorScript is Script, CreateXScript {
    // ---------------------------------------------------------------------
    // Configuration
    // ---------------------------------------------------------------------

    // A fixed salt guarantees that equal (byte-code, salt) pairs resolve to the
    // same address on every chain. Change the value only if you explicitly need
    // a different deployment slot.
    bytes32 internal constant SALT = bytes32(0);

    // Public variables are handy when you want to inspect the result with
    // `forge inspect <script> <variable-name>` after the run.
    address public predicted;
    address public deployed;

    // ---------------------------------------------------------------------
    // setUp – executed first by forge-std
    // ---------------------------------------------------------------------
    // The `withCreateX` modifier (defined in CreateXScript) verifies that the
    // factory lives at 0xba5E…ba5Ed. When you run the script inside Forge's
    // in-memory VM (chain-id 31337) it will even *etch* the factory for you so
    // that local dry-runs behave exactly like main-net deployments.
    function setUp() public withCreateX {}

    // ---------------------------------------------------------------------
    // run – the actual deployment logic
    // ---------------------------------------------------------------------
    function run() external {
        // 1. Build the creation (init) code for the target contract.
        bytes memory initCode = type(SiglessTransactionExecutor).creationCode;

        // 2. Pre-compute the address the contract will occupy after CREATE2.
        //    Formula: keccak256(0xFF ++ factory ++ salt ++ keccak256(initCode))[12:]
        //    The helper on the factory does this for us.
        predicted = CreateX.computeCreate2Address(
            keccak256(abi.encode(SALT)), // CREATEX's salt generation logic for unprotected contracts
            keccak256(initCode),
            address(CreateX) // The factory is the deployer for CREATE2.
        );

        console2.log("Expected SiglessTransactionExecutor address:", predicted);

        // 3. Send the transaction(s) to the network.
        vm.startBroadcast();

        // 4. Deterministically deploy the contract via the factory.
        deployed = CreateX.deployCreate2(SALT, initCode);

        vm.stopBroadcast();

        // 5. Sanity check – make sure nothing unexpected happened (e.g. someone
        //    pre-deployed different byte-code at the same address).
        require(deployed == predicted, "Create2: deployed address does not match prediction");

        console2.log("SiglessTransactionExecutor deployed at:", deployed);
    }
}
