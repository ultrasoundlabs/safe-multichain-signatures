// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {CreateXScript} from "createx-forge/script/CreateXScript.sol";
import {MultiChainSignaturesModule} from "../src/modules/MultiChainSignaturesModule.sol";
import {SiglessTransactionExecutor} from "../src/libraries/SiglessTransactionExecutor.sol";

/// @title MultiChainSignaturesModule deterministic deployer
/// @notice Anyone can run this script on any EVM network and obtain the exact
///         same contract address (provided the byte-code and salt stay the same).
///         We use the universal CreateX factory together with the CREATE2 opcode.
contract MultiChainSignaturesModuleScript is Script, CreateXScript {
    // ---------------------------------------------------------------------
    // Configuration
    // ---------------------------------------------------------------------

    // === salts ===========================================================
    // Keep the salts in one place so that computing addresses for dependent
    // deployments stays trivial.
    bytes32 internal constant SALT = bytes32(0);
    bytes32 internal constant SIGLESS_SALT = bytes32(0); // must match the one used in SiglessTransactionExecutorScript

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
        // ------------------------------------------------------------------
        // Derive the deterministic address of SiglessTransactionExecutor.
        // ------------------------------------------------------------------
        address siglessPredicted = CreateX.computeCreate2Address(
            keccak256(abi.encode(SIGLESS_SALT)), // CREATEX's salt generation logic for unprotected contracts
            keccak256(type(SiglessTransactionExecutor).creationCode),
            address(CreateX)
        );

        console2.log("Using SiglessTransactionExecutor at:", siglessPredicted);

        // ------------------------------------------------------------------
        // 1. Build the creation (init) code WITH constructor args.
        // ------------------------------------------------------------------
        bytes memory initCode =
            abi.encodePacked(type(MultiChainSignaturesModule).creationCode, abi.encode(siglessPredicted));

        // ------------------------------------------------------------------
        // 2. Pre-compute the CREATE2 address for this byte-code / salt pair.
        // ------------------------------------------------------------------
        predicted = CreateX.computeCreate2Address(
            keccak256(abi.encode(SALT)), // CREATEX's salt generation logic for unprotected contracts
            keccak256(initCode),
            address(CreateX)
        );

        console2.log("Expected MultiChainSignaturesModule address:", predicted);

        // ------------------------------------------------------------------
        // 3. Broadcast the deployment.
        // ------------------------------------------------------------------
        vm.startBroadcast();

        deployed = CreateX.deployCreate2(SALT, initCode);

        vm.stopBroadcast();

        // ------------------------------------------------------------------
        // 4. Sanity check.
        // ------------------------------------------------------------------
        require(deployed == predicted, "Address mismatch after deploy");

        console2.log("MultiChainSignaturesModule deployed at:", deployed);
    }
}
