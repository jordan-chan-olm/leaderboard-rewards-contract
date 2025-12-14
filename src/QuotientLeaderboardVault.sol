// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "solady/auth/Ownable.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

/// @title QuotientLeaderboardVault
/// @notice A campaign-based reward vault with EIP-712 signature verification
/// @dev Sponsors fund campaigns, backend signs claim authorizations, users claim rewards
contract QuotientLeaderboardVault is Ownable, EIP712 {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Address of the backend signer that authorizes claims
    address public signer;

    /// @notice Maps campaign ID to the ERC-20 token address
    mapping(uint256 => address) public campaignTokens;

    /// @notice Tracks if a user has already claimed for a specific campaign
    mapping(uint256 => mapping(address => bool)) public hasClaimed;

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice EIP-712 typehash for claim struct
    bytes32 public constant CLAIM_TYPEHASH =
        keccak256("Claim(uint256 campaignId,address claimant,uint256 amount)");

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error AlreadyClaimed();
    error CampaignNotActive();
    error CampaignAlreadyExists();
    error CampaignNotFound();
    error InvalidSignature();
    error InvalidSigner();
    error InvalidAmount();
    error InvalidToken();

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event CampaignSetup(uint256 indexed campaignId, address indexed token);
    event CampaignUpdated(uint256 indexed campaignId, address indexed oldToken, address indexed newToken);
    event CampaignPaused(uint256 indexed campaignId);
    event Payout(uint256 indexed campaignId, address indexed claimant, uint256 amount);
    event SignerUpdated(address indexed newSigner);

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param initialOwner The address that will own this contract
    /// @param initialSigner The initial backend signer address
    constructor(address initialOwner, address initialSigner) {
        _initializeOwner(initialOwner);
        if (initialSigner == address(0)) revert InvalidSigner();
        signer = initialSigner;
        emit SignerUpdated(initialSigner);
    }

    /*//////////////////////////////////////////////////////////////
                           EIP-712 DOMAIN
    //////////////////////////////////////////////////////////////*/

    /// @dev Returns the EIP-712 domain name and version
    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "QuotientLeaderboardVault";
        version = "1";
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets up a NEW campaign with a specific token
    /// @param id The campaign ID
    /// @param token The ERC-20 token address for this campaign
    /// @dev Reverts if campaign already exists. Use updateCampaignToken to modify existing.
    function setupCampaign(uint256 id, address token) external onlyOwner {
        if (campaignTokens[id] != address(0)) revert CampaignAlreadyExists();
        if (token == address(0)) revert InvalidToken();
        campaignTokens[id] = token;
        emit CampaignSetup(id, token);
    }

    /// @notice Updates the token for an EXISTING campaign
    /// @param id The campaign ID
    /// @param newToken The new ERC-20 token address
    /// @dev Use with caution - existing signatures will transfer the new token
    function updateCampaignToken(uint256 id, address newToken) external onlyOwner {
        address oldToken = campaignTokens[id];
        if (oldToken == address(0)) revert CampaignNotFound();
        if (newToken == address(0)) revert InvalidToken();
        campaignTokens[id] = newToken;
        emit CampaignUpdated(id, oldToken, newToken);
    }

    /// @notice Pauses a campaign by setting its token to address(0)
    /// @param id The campaign ID to pause
    /// @dev Claims will revert with CampaignNotActive after pausing
    function pauseCampaign(uint256 id) external onlyOwner {
        if (campaignTokens[id] == address(0)) revert CampaignNotFound();
        campaignTokens[id] = address(0);
        emit CampaignPaused(id);
    }

    /// @notice Updates the backend signer address
    /// @param newSigner The new signer address
    function setSigner(address newSigner) external onlyOwner {
        if (newSigner == address(0)) revert InvalidSigner();
        signer = newSigner;
        emit SignerUpdated(newSigner);
    }

    /// @notice Emergency function to rescue tokens
    /// @param token The token address to rescue
    /// @param amount The amount to rescue
    function rescueFunds(address token, uint256 amount) external onlyOwner {
        SafeTransferLib.safeTransfer(token, msg.sender, amount);
    }

    /*//////////////////////////////////////////////////////////////
                            CLAIM FUNCTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Claim rewards for a campaign with a valid signature
    /// @param campaignId The campaign ID to claim from
    /// @param amount The amount to claim (must match signed amount)
    /// @param signature The EIP-712 signature from the backend signer
    function claim(uint256 campaignId, uint256 amount, bytes calldata signature) external {
        // 1. Check amount is non-zero
        if (amount == 0) revert InvalidAmount();

        // 2. Check not already claimed
        if (hasClaimed[campaignId][msg.sender]) revert AlreadyClaimed();

        // 3. Check campaign exists
        address token = campaignTokens[campaignId];
        if (token == address(0)) revert CampaignNotActive();

        // 4. Build EIP-712 digest
        bytes32 structHash = keccak256(abi.encode(CLAIM_TYPEHASH, campaignId, msg.sender, amount));
        bytes32 digest = _hashTypedData(structHash);

        // 5. Recover and verify signer
        address recovered = ECDSA.recover(digest, signature);
        if (recovered != signer) revert InvalidSignature();

        // 6. Mark as claimed
        hasClaimed[campaignId][msg.sender] = true;

        // 7. Transfer tokens
        SafeTransferLib.safeTransfer(token, msg.sender, amount);

        // 8. Emit event
        emit Payout(campaignId, msg.sender, amount);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the EIP-712 domain separator
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

    /// @notice Computes the digest for a claim (for backend signature generation)
    /// @param campaignId The campaign ID
    /// @param claimant The address that will claim
    /// @param amount The amount to claim
    /// @return The EIP-712 digest to sign
    function getClaimDigest(
        uint256 campaignId,
        address claimant,
        uint256 amount
    ) external view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(CLAIM_TYPEHASH, campaignId, claimant, amount));
        return _hashTypedData(structHash);
    }
}
