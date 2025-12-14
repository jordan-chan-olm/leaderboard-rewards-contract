// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {QuotientLeaderboardVault} from "../src/QuotientLeaderboardVault.sol";

contract DeployScript is Script {
    function run() external returns (QuotientLeaderboardVault vault) {
        address signer = vm.envAddress("SIGNER_ADDRESS");
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying QuotientLeaderboardVault...");
        console.log("  Deployer:", deployer);
        console.log("  Signer:", signer);
        console.log("  Chain ID:", block.chainid);

        vm.startBroadcast(deployerPrivateKey);
        vault = new QuotientLeaderboardVault(msg.sender, signer);
        vm.stopBroadcast();

        console.log("Deployed to:", address(vault));
        console.log("Domain Separator:", vm.toString(vault.DOMAIN_SEPARATOR()));

        return vault;
    }
}
