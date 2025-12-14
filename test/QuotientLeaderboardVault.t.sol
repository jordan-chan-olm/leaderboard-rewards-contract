// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {QuotientLeaderboardVault} from "../src/QuotientLeaderboardVault.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract QuotientLeaderboardVaultTest is Test {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    QuotientLeaderboardVault public vault;
    MockERC20 public token;

    // Test accounts
    address public owner;
    uint256 public signerPrivateKey;
    address public signerAddress;
    address public user1;
    address public user2;
    address public randomUser;

    // Campaign IDs
    uint256 public constant CAMPAIGN_ID_1 = 1;
    uint256 public constant CAMPAIGN_ID_2 = 2;

    // Amounts
    uint256 public constant CLAIM_AMOUNT = 100e6; // 100 USDC (6 decimals)
    uint256 public constant VAULT_FUNDING = 10_000e6; // 10,000 USDC

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        // Set up accounts
        owner = makeAddr("owner");
        signerPrivateKey = 0xA11CE;
        signerAddress = vm.addr(signerPrivateKey);
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        randomUser = makeAddr("randomUser");

        // Deploy token
        token = new MockERC20("USD Coin", "USDC", 6);

        // Deploy vault
        vm.prank(owner);
        vault = new QuotientLeaderboardVault(owner, signerAddress);
    }

    /*//////////////////////////////////////////////////////////////
                          SIGNATURE HELPERS
    //////////////////////////////////////////////////////////////*/

    function _getClaimSignature(
        uint256 campaignId,
        address claimant,
        uint256 amount,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        bytes32 digest = vault.getClaimDigest(campaignId, claimant, amount);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Constructor() public view {
        assertEq(vault.owner(), owner);
        assertEq(vault.signer(), signerAddress);
    }

    function test_Constructor_RevertZeroSigner() public {
        vm.prank(owner);
        vm.expectRevert(QuotientLeaderboardVault.InvalidSigner.selector);
        new QuotientLeaderboardVault(owner, address(0));
    }

    function test_Constructor_EmitsSignerUpdated() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit QuotientLeaderboardVault.SignerUpdated(signerAddress);
        new QuotientLeaderboardVault(owner, signerAddress);
    }

    /*//////////////////////////////////////////////////////////////
                        SETUP CAMPAIGN TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetupCampaign_Success() public {
        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit QuotientLeaderboardVault.CampaignSetup(CAMPAIGN_ID_1, address(token));
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));

        assertEq(vault.campaignTokens(CAMPAIGN_ID_1), address(token));
    }

    function test_SetupCampaign_RevertNonOwner() public {
        vm.prank(randomUser);
        vm.expectRevert();
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
    }

    function test_SetupCampaign_RevertAlreadyExists() public {
        vm.startPrank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));

        vm.expectRevert(QuotientLeaderboardVault.CampaignAlreadyExists.selector);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        vm.stopPrank();
    }

    function test_SetupCampaign_RevertZeroToken() public {
        vm.prank(owner);
        vm.expectRevert(QuotientLeaderboardVault.InvalidToken.selector);
        vault.setupCampaign(CAMPAIGN_ID_1, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                      UPDATE CAMPAIGN TOKEN TESTS
    //////////////////////////////////////////////////////////////*/

    function test_UpdateCampaignToken_Success() public {
        MockERC20 newToken = new MockERC20("New Token", "NEW", 18);

        vm.startPrank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));

        vm.expectEmit(true, true, true, false);
        emit QuotientLeaderboardVault.CampaignUpdated(CAMPAIGN_ID_1, address(token), address(newToken));
        vault.updateCampaignToken(CAMPAIGN_ID_1, address(newToken));

        assertEq(vault.campaignTokens(CAMPAIGN_ID_1), address(newToken));
        vm.stopPrank();
    }

    function test_UpdateCampaignToken_RevertNonOwner() public {
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));

        vm.prank(randomUser);
        vm.expectRevert();
        vault.updateCampaignToken(CAMPAIGN_ID_1, address(token));
    }

    function test_UpdateCampaignToken_RevertNotFound() public {
        vm.prank(owner);
        vm.expectRevert(QuotientLeaderboardVault.CampaignNotFound.selector);
        vault.updateCampaignToken(CAMPAIGN_ID_1, address(token));
    }

    function test_UpdateCampaignToken_RevertZeroToken() public {
        vm.startPrank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));

        vm.expectRevert(QuotientLeaderboardVault.InvalidToken.selector);
        vault.updateCampaignToken(CAMPAIGN_ID_1, address(0));
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        PAUSE CAMPAIGN TESTS
    //////////////////////////////////////////////////////////////*/

    function test_PauseCampaign_Success() public {
        vm.startPrank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));

        vm.expectEmit(true, false, false, false);
        emit QuotientLeaderboardVault.CampaignPaused(CAMPAIGN_ID_1);
        vault.pauseCampaign(CAMPAIGN_ID_1);

        assertEq(vault.campaignTokens(CAMPAIGN_ID_1), address(0));
        vm.stopPrank();
    }

    function test_PauseCampaign_RevertNonOwner() public {
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));

        vm.prank(randomUser);
        vm.expectRevert();
        vault.pauseCampaign(CAMPAIGN_ID_1);
    }

    function test_PauseCampaign_RevertNotFound() public {
        vm.prank(owner);
        vm.expectRevert(QuotientLeaderboardVault.CampaignNotFound.selector);
        vault.pauseCampaign(CAMPAIGN_ID_1);
    }

    function test_PauseCampaign_ClaimReverts() public {
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        token.mint(address(vault), VAULT_FUNDING);

        // Pause the campaign
        vm.prank(owner);
        vault.pauseCampaign(CAMPAIGN_ID_1);

        // Try to claim - should revert
        bytes memory signature = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, signerPrivateKey);
        vm.prank(user1);
        vm.expectRevert(QuotientLeaderboardVault.CampaignNotActive.selector);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, signature);
    }

    /*//////////////////////////////////////////////////////////////
                          SET SIGNER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetSigner_Success() public {
        address newSigner = makeAddr("newSigner");

        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit QuotientLeaderboardVault.SignerUpdated(newSigner);
        vault.setSigner(newSigner);

        assertEq(vault.signer(), newSigner);
    }

    function test_SetSigner_RevertNonOwner() public {
        vm.prank(randomUser);
        vm.expectRevert();
        vault.setSigner(makeAddr("newSigner"));
    }

    function test_SetSigner_RevertZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(QuotientLeaderboardVault.InvalidSigner.selector);
        vault.setSigner(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                          CLAIM TESTS - CORE
    //////////////////////////////////////////////////////////////*/

    function test_Claim_Success() public {
        // Setup: campaign and funding
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        token.mint(address(vault), VAULT_FUNDING);

        // Generate signature
        bytes memory signature = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, signerPrivateKey);

        // Claim
        vm.prank(user1);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, signature);

        // Assertions
        assertEq(token.balanceOf(user1), CLAIM_AMOUNT);
        assertTrue(vault.hasClaimed(CAMPAIGN_ID_1, user1));
    }

    function test_Claim_EmitsPayoutEvent() public {
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        token.mint(address(vault), VAULT_FUNDING);

        bytes memory signature = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, signerPrivateKey);

        vm.prank(user1);
        vm.expectEmit(true, true, false, true);
        emit QuotientLeaderboardVault.Payout(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, signature);
    }

    /*//////////////////////////////////////////////////////////////
                       CLAIM TESTS - SECURITY
    //////////////////////////////////////////////////////////////*/

    function test_Revert_InvalidSignature() public {
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        token.mint(address(vault), VAULT_FUNDING);

        // Sign with random key
        uint256 randomKey = 0xDEAD;
        bytes memory badSignature = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, randomKey);

        vm.prank(user1);
        vm.expectRevert(QuotientLeaderboardVault.InvalidSignature.selector);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, badSignature);
    }

    function test_Revert_WrongUser() public {
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        token.mint(address(vault), VAULT_FUNDING);

        // Generate signature for user1
        bytes memory signatureForUser1 = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, signerPrivateKey);

        // user2 tries to use user1's signature (front-running attempt)
        vm.prank(user2);
        vm.expectRevert(QuotientLeaderboardVault.InvalidSignature.selector);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, signatureForUser1);
    }

    function test_Revert_DoubleClaim() public {
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        token.mint(address(vault), VAULT_FUNDING);

        bytes memory signature = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, signerPrivateKey);

        // First claim succeeds
        vm.prank(user1);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, signature);

        // Second claim fails
        vm.prank(user1);
        vm.expectRevert(QuotientLeaderboardVault.AlreadyClaimed.selector);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, signature);
    }

    function test_Revert_WrongAmount() public {
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        token.mint(address(vault), VAULT_FUNDING);

        // Signature for 100 tokens
        bytes memory signature = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, signerPrivateKey);

        // Try to claim 200 tokens
        vm.prank(user1);
        vm.expectRevert(QuotientLeaderboardVault.InvalidSignature.selector);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT * 2, signature);
    }

    function test_Revert_WrongCampaignId() public {
        vm.startPrank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        vault.setupCampaign(CAMPAIGN_ID_2, address(token));
        vm.stopPrank();
        token.mint(address(vault), VAULT_FUNDING);

        // Signature for campaign 1
        bytes memory signature = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, signerPrivateKey);

        // Try to claim from campaign 2
        vm.prank(user1);
        vm.expectRevert(QuotientLeaderboardVault.InvalidSignature.selector);
        vault.claim(CAMPAIGN_ID_2, CLAIM_AMOUNT, signature);
    }

    function test_Revert_CampaignNotActive() public {
        // Campaign not set up
        bytes memory signature = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, signerPrivateKey);

        vm.prank(user1);
        vm.expectRevert(QuotientLeaderboardVault.CampaignNotActive.selector);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, signature);
    }

    function test_Revert_VaultUnderfunded() public {
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        // Vault has 0 tokens

        bytes memory signature = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, signerPrivateKey);

        vm.prank(user1);
        vm.expectRevert(); // ERC20 transfer will fail
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, signature);
    }

    function test_Revert_ZeroAmount() public {
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        token.mint(address(vault), VAULT_FUNDING);

        bytes memory signature = _getClaimSignature(CAMPAIGN_ID_1, user1, 0, signerPrivateKey);

        vm.prank(user1);
        vm.expectRevert(QuotientLeaderboardVault.InvalidAmount.selector);
        vault.claim(CAMPAIGN_ID_1, 0, signature);
    }

    /*//////////////////////////////////////////////////////////////
                        RESCUE FUNDS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RescueFunds_Success() public {
        token.mint(address(vault), VAULT_FUNDING);

        vm.prank(owner);
        vault.rescueFunds(address(token), VAULT_FUNDING);

        assertEq(token.balanceOf(owner), VAULT_FUNDING);
        assertEq(token.balanceOf(address(vault)), 0);
    }

    function test_RescueFunds_RevertNonOwner() public {
        token.mint(address(vault), VAULT_FUNDING);

        vm.prank(randomUser);
        vm.expectRevert();
        vault.rescueFunds(address(token), VAULT_FUNDING);
    }

    function test_RescueFunds_PartialWithdraw() public {
        token.mint(address(vault), VAULT_FUNDING);
        uint256 partialAmount = VAULT_FUNDING / 2;

        vm.prank(owner);
        vault.rescueFunds(address(token), partialAmount);

        assertEq(token.balanceOf(owner), partialAmount);
        assertEq(token.balanceOf(address(vault)), VAULT_FUNDING - partialAmount);
    }

    function test_RescueFunds_DifferentToken() public {
        MockERC20 anotherToken = new MockERC20("Another", "ANO", 18);
        anotherToken.mint(address(vault), 1000e18);

        vm.prank(owner);
        vault.rescueFunds(address(anotherToken), 1000e18);

        assertEq(anotherToken.balanceOf(owner), 1000e18);
    }

    /*//////////////////////////////////////////////////////////////
                       ADDITIONAL EDGE CASES
    //////////////////////////////////////////////////////////////*/

    function test_Claim_MultipleCampaigns() public {
        MockERC20 token2 = new MockERC20("Token 2", "TK2", 18);

        vm.startPrank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        vault.setupCampaign(CAMPAIGN_ID_2, address(token2));
        vm.stopPrank();

        token.mint(address(vault), VAULT_FUNDING);
        token2.mint(address(vault), 1000e18);

        // Claim from campaign 1
        bytes memory sig1 = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, signerPrivateKey);
        vm.prank(user1);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, sig1);

        // Claim from campaign 2
        uint256 amount2 = 500e18;
        bytes memory sig2 = _getClaimSignature(CAMPAIGN_ID_2, user1, amount2, signerPrivateKey);
        vm.prank(user1);
        vault.claim(CAMPAIGN_ID_2, amount2, sig2);

        assertEq(token.balanceOf(user1), CLAIM_AMOUNT);
        assertEq(token2.balanceOf(user1), amount2);
        assertTrue(vault.hasClaimed(CAMPAIGN_ID_1, user1));
        assertTrue(vault.hasClaimed(CAMPAIGN_ID_2, user1));
    }

    function test_Claim_MultipleUsers() public {
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        token.mint(address(vault), VAULT_FUNDING);

        // User 1 claims
        bytes memory sig1 = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, signerPrivateKey);
        vm.prank(user1);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, sig1);

        // User 2 claims different amount
        uint256 user2Amount = 200e6;
        bytes memory sig2 = _getClaimSignature(CAMPAIGN_ID_1, user2, user2Amount, signerPrivateKey);
        vm.prank(user2);
        vault.claim(CAMPAIGN_ID_1, user2Amount, sig2);

        assertEq(token.balanceOf(user1), CLAIM_AMOUNT);
        assertEq(token.balanceOf(user2), user2Amount);
    }

    function test_Claim_AfterSignerChange() public {
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        token.mint(address(vault), VAULT_FUNDING);

        // Generate signature with old signer
        bytes memory oldSignature = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, signerPrivateKey);

        // Change signer
        uint256 newSignerKey = 0xBEEF;
        address newSignerAddress = vm.addr(newSignerKey);
        vm.prank(owner);
        vault.setSigner(newSignerAddress);

        // Old signature should fail
        vm.prank(user1);
        vm.expectRevert(QuotientLeaderboardVault.InvalidSignature.selector);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, oldSignature);

        // New signature should work
        bytes memory newSignature = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, newSignerKey);
        vm.prank(user1);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, newSignature);

        assertEq(token.balanceOf(user1), CLAIM_AMOUNT);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW HELPER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_DOMAIN_SEPARATOR() public view {
        bytes32 separator = vault.DOMAIN_SEPARATOR();
        assertTrue(separator != bytes32(0));
    }

    function test_GetClaimDigest() public view {
        bytes32 digest1 = vault.getClaimDigest(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT);
        bytes32 digest2 = vault.getClaimDigest(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT);

        // Same inputs should give same digest
        assertEq(digest1, digest2);

        // Different inputs should give different digest
        bytes32 differentAmount = vault.getClaimDigest(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT + 1);
        assertTrue(digest1 != differentAmount);

        bytes32 differentUser = vault.getClaimDigest(CAMPAIGN_ID_1, user2, CLAIM_AMOUNT);
        assertTrue(digest1 != differentUser);

        bytes32 differentCampaign = vault.getClaimDigest(CAMPAIGN_ID_2, user1, CLAIM_AMOUNT);
        assertTrue(digest1 != differentCampaign);
    }

    /*//////////////////////////////////////////////////////////////
                       INTEGRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_FullFlow() public {
        // 1. Admin sets up campaign
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));

        // 2. Sponsor funds vault (direct transfer)
        token.mint(address(vault), VAULT_FUNDING);

        // 3. Backend generates signature for user (simulated)
        bytes memory signature = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, signerPrivateKey);

        // 4. User claims
        uint256 balanceBefore = token.balanceOf(user1);
        vm.prank(user1);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, signature);
        uint256 balanceAfter = token.balanceOf(user1);

        // 5. Verify
        assertEq(balanceAfter - balanceBefore, CLAIM_AMOUNT);
        assertTrue(vault.hasClaimed(CAMPAIGN_ID_1, user1));
        assertEq(token.balanceOf(address(vault)), VAULT_FUNDING - CLAIM_AMOUNT);
    }

    function test_MultiCampaignFlow() public {
        MockERC20 usdt = new MockERC20("Tether", "USDT", 6);

        // Setup multiple campaigns
        vm.startPrank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token)); // USDC campaign
        vault.setupCampaign(CAMPAIGN_ID_2, address(usdt)); // USDT campaign
        vm.stopPrank();

        // Fund vault
        token.mint(address(vault), 5000e6);
        usdt.mint(address(vault), 5000e6);

        // Multiple users claim from multiple campaigns
        address[] memory users = new address[](3);
        users[0] = user1;
        users[1] = user2;
        users[2] = randomUser;

        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount = (i + 1) * 50e6; // 50, 100, 150

            // Claim from USDC campaign
            bytes memory sig = _getClaimSignature(CAMPAIGN_ID_1, users[i], amount, signerPrivateKey);
            vm.prank(users[i]);
            vault.claim(CAMPAIGN_ID_1, amount, sig);

            // Claim from USDT campaign
            bytes memory sig2 = _getClaimSignature(CAMPAIGN_ID_2, users[i], amount, signerPrivateKey);
            vm.prank(users[i]);
            vault.claim(CAMPAIGN_ID_2, amount, sig2);

            assertEq(token.balanceOf(users[i]), amount);
            assertEq(usdt.balanceOf(users[i]), amount);
        }
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_Claim(uint256 amount) public {
        // Bound amount to reasonable values (non-zero, less than vault funding)
        amount = bound(amount, 1, VAULT_FUNDING);

        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        token.mint(address(vault), VAULT_FUNDING);

        bytes memory signature = _getClaimSignature(CAMPAIGN_ID_1, user1, amount, signerPrivateKey);

        vm.prank(user1);
        vault.claim(CAMPAIGN_ID_1, amount, signature);

        assertEq(token.balanceOf(user1), amount);
        assertTrue(vault.hasClaimed(CAMPAIGN_ID_1, user1));
    }

    function testFuzz_CampaignId(uint256 campaignId) public {
        vm.prank(owner);
        vault.setupCampaign(campaignId, address(token));
        token.mint(address(vault), VAULT_FUNDING);

        bytes memory signature = _getClaimSignature(campaignId, user1, CLAIM_AMOUNT, signerPrivateKey);

        vm.prank(user1);
        vault.claim(campaignId, CLAIM_AMOUNT, signature);

        assertEq(token.balanceOf(user1), CLAIM_AMOUNT);
        assertTrue(vault.hasClaimed(campaignId, user1));
    }

    /*//////////////////////////////////////////////////////////////
                     ADDITIONAL SECURITY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test that tokens with different decimals work correctly
    function test_TokenDecimals_HighDecimals() public {
        // 18 decimal token (like most ERC20s)
        MockERC20 highDecToken = new MockERC20("High Dec", "HIGH", 18);
        uint256 amount = 100e18; // 100 tokens with 18 decimals

        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(highDecToken));
        highDecToken.mint(address(vault), 1000e18);

        bytes memory signature = _getClaimSignature(CAMPAIGN_ID_1, user1, amount, signerPrivateKey);

        vm.prank(user1);
        vault.claim(CAMPAIGN_ID_1, amount, signature);

        assertEq(highDecToken.balanceOf(user1), amount);
    }

    function test_TokenDecimals_LowDecimals() public {
        // 6 decimal token (like USDC/USDT)
        MockERC20 lowDecToken = new MockERC20("Low Dec", "LOW", 6);
        uint256 amount = 100e6; // 100 tokens with 6 decimals

        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(lowDecToken));
        lowDecToken.mint(address(vault), 1000e6);

        bytes memory signature = _getClaimSignature(CAMPAIGN_ID_1, user1, amount, signerPrivateKey);

        vm.prank(user1);
        vault.claim(CAMPAIGN_ID_1, amount, signature);

        assertEq(lowDecToken.balanceOf(user1), amount);
    }

    function test_TokenDecimals_ZeroDecimals() public {
        // 0 decimal token (rare but exists)
        MockERC20 zeroDecToken = new MockERC20("Zero Dec", "ZERO", 0);
        uint256 amount = 100; // 100 whole tokens

        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(zeroDecToken));
        zeroDecToken.mint(address(vault), 1000);

        bytes memory signature = _getClaimSignature(CAMPAIGN_ID_1, user1, amount, signerPrivateKey);

        vm.prank(user1);
        vault.claim(CAMPAIGN_ID_1, amount, signature);

        assertEq(zeroDecToken.balanceOf(user1), amount);
    }

    /// @notice Test signature replay protection - malleable signatures don't enable double claims
    /// @dev Solady ECDSA accepts both high and low s values (both recover correctly).
    ///      Security comes from: 1) claimant in hash prevents stealing, 2) hasClaimed prevents replay
    function test_SignatureMalleability_NoDoubleClaimWithMalleableSignature() public {
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        token.mint(address(vault), VAULT_FUNDING);

        // Get valid signature
        bytes32 digest = vault.getClaimDigest(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // First claim with original signature succeeds
        vm.prank(user1);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, signature);

        // Compute malleable signature (s' = secp256k1n - s)
        uint256 secp256k1n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        uint256 malleableS = secp256k1n - uint256(s);
        uint8 malleableV = v == 27 ? 28 : 27;
        bytes memory malleableSignature = abi.encodePacked(r, bytes32(malleableS), malleableV);

        // Second claim with malleable signature should fail (already claimed)
        vm.prank(user1);
        vm.expectRevert(QuotientLeaderboardVault.AlreadyClaimed.selector);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, malleableSignature);

        // User only received tokens once
        assertEq(token.balanceOf(user1), CLAIM_AMOUNT);
    }

    /// @notice Explicit test: Front-running protection via msg.sender in hash
    function test_FrontRunning_ExplicitProtection() public {
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        token.mint(address(vault), VAULT_FUNDING);

        // Backend signs for user1
        bytes memory signatureForUser1 = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, signerPrivateKey);

        // Attacker (user2) sees the transaction in mempool and tries to front-run
        // They copy the signature and try to claim for themselves
        vm.prank(user2);
        vm.expectRevert(QuotientLeaderboardVault.InvalidSignature.selector);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, signatureForUser1);

        // Original user1 can still claim
        vm.prank(user1);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, signatureForUser1);

        assertEq(token.balanceOf(user1), CLAIM_AMOUNT);
        assertEq(token.balanceOf(user2), 0);
    }

    /// @notice Test that griefing via signature copying doesn't work
    function test_Griefing_SignatureCopyingFails() public {
        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));
        token.mint(address(vault), VAULT_FUNDING);

        // Signatures for different users
        bytes memory sigUser1 = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, signerPrivateKey);
        bytes memory sigUser2 = _getClaimSignature(CAMPAIGN_ID_1, user2, CLAIM_AMOUNT, signerPrivateKey);

        // Each signature only works for its designated user
        vm.prank(user1);
        vm.expectRevert(QuotientLeaderboardVault.InvalidSignature.selector);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, sigUser2);

        vm.prank(user2);
        vm.expectRevert(QuotientLeaderboardVault.InvalidSignature.selector);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, sigUser1);

        // But each works for the correct user
        vm.prank(user1);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, sigUser1);

        vm.prank(user2);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, sigUser2);
    }

    /// @notice Test EIP-712 domain separation (different chain = different digest)
    function test_EIP712_ChainIdProtection() public {
        // Get digest on current chain
        bytes32 digest1 = vault.getClaimDigest(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT);

        // Fork to different chain ID
        vm.chainId(999);

        // Digest should be different on different chain
        bytes32 digest2 = vault.getClaimDigest(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT);

        assertTrue(digest1 != digest2, "Digests should differ across chains");
    }

    /// @notice Test claiming after campaign token update (warning scenario)
    function test_CampaignUpdate_SignatureStillValid() public {
        MockERC20 newToken = new MockERC20("New Token", "NEW", 18);

        vm.prank(owner);
        vault.setupCampaign(CAMPAIGN_ID_1, address(token));

        // Generate signature while token is USDC
        bytes memory signature = _getClaimSignature(CAMPAIGN_ID_1, user1, CLAIM_AMOUNT, signerPrivateKey);

        // Admin updates to different token (the risky operation we're documenting)
        vm.prank(owner);
        vault.updateCampaignToken(CAMPAIGN_ID_1, address(newToken));

        // Fund vault with new token
        newToken.mint(address(vault), VAULT_FUNDING);

        // User claims - they get the NEW token, not the one they expected
        vm.prank(user1);
        vault.claim(CAMPAIGN_ID_1, CLAIM_AMOUNT, signature);

        // User received the new token (this is the documented risk)
        assertEq(newToken.balanceOf(user1), CLAIM_AMOUNT);
        assertEq(token.balanceOf(user1), 0);
    }
}
