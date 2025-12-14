# Quotient Leaderboard Vault

A gas-optimized ERC-20 reward vault with EIP-712 signature-based claims. Sponsors fund campaigns, the backend authorizes payouts via signatures, and users claim their rewards trustlessly.

## Overview

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Sponsor   │     │    Admin    │     │   Backend   │     │    User     │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │                   │
       │ Transfer USDC     │                   │                   │
       │──────────────────>│ setupCampaign()   │                   │
       │                   │──────────────────>│                   │
       │                   │                   │                   │
       │                   │                   │ Calculate rewards │
       │                   │                   │<─────────────────>│
       │                   │                   │                   │
       │                   │                   │ Sign claim data   │
       │                   │                   │──────────────────>│
       │                   │                   │                   │
       │                   │                   │      claim()      │
       │                   │                   │<──────────────────│
       │                   │                   │                   │
       │                   │                   │  Transfer tokens  │
       │                   │                   │──────────────────>│
       └───────────────────┴───────────────────┴───────────────────┘
```

## Contract Features

- **Gas Optimized**: Built with [Solady](https://github.com/vectorized/solady) libraries
- **EIP-712 Signatures**: Type-safe, human-readable signature requests
- **Front-running Protected**: Claimant address is part of signed data
- **Double-claim Protected**: `hasClaimed` mapping prevents replay
- **Multi-campaign Support**: Run multiple campaigns with different tokens
- **Admin Controls**: Setup, update, pause campaigns + emergency rescue

## Installation

```bash
# Clone the repo
git clone git@github.com:jchanolm/leaderboard-rewards-contract.git
cd leaderboard-rewards-contract

# Install dependencies
forge install

# Build
forge build

# Test
forge test
```

## Deployment

### 1. Configure Environment

```bash
cp .env.example .env
# Edit .env with your values
source .env
```

### 2. Deploy to Base

```bash
# Dry run (simulation)
forge script script/Deploy.s.sol:DeployScript \
  --rpc-url https://mainnet.base.org \
  --private-key $PRIVATE_KEY

# Deploy and verify
forge script script/Deploy.s.sol:DeployScript \
  --rpc-url https://mainnet.base.org \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify \
  --etherscan-api-key $ETHERSCAN_API_KEY
```

### 3. Verify Existing Contract

If you deployed without `--verify`:

```bash
forge verify-contract \
  --chain-id 8453 \
  --constructor-args $(cast abi-encode "constructor(address,address)" $(cast wallet address --private-key $PRIVATE_KEY) $SIGNER_ADDRESS) \
  --etherscan-api-key $ETHERSCAN_API_KEY \
  0xDeployedContractAddress \
  src/QuotientLeaderboardVault.sol:QuotientLeaderboardVault
```

### 4. Post-Deployment Checklist

```bash
export VAULT=0xYourDeployedContractAddress

# Check owner
cast call $VAULT "owner()" --rpc-url https://mainnet.base.org

# Check signer
cast call $VAULT "signer()" --rpc-url https://mainnet.base.org

# Check domain separator (for backend)
cast call $VAULT "DOMAIN_SEPARATOR()" --rpc-url https://mainnet.base.org
```

---

## Admin Operations

### Using Cast (Foundry CLI)

```bash
# Ensure .env is loaded (source .env) and set vault address
export VAULT=0xYourVaultAddress
export RPC=https://mainnet.base.org

# Setup a new campaign (ID: 1, Token: USDC on Base)
cast send $VAULT "setupCampaign(uint256,address)" 1 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 \
  --rpc-url $RPC --private-key $PRIVATE_KEY

# Fund the vault (transfer USDC to vault address)
# setupCampaign only registers the token - you must fund separately
cast send 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 "transfer(address,uint256)" $VAULT 10000000000 \
  --rpc-url $RPC --private-key $PRIVATE_KEY  # 10,000 USDC (6 decimals)

# Update campaign token
cast send $VAULT "updateCampaignToken(uint256,address)" 1 0xNEW_TOKEN \
  --rpc-url $RPC --private-key $PRIVATE_KEY

# Pause a campaign (stops all claims)
cast send $VAULT "pauseCampaign(uint256)" 1 \
  --rpc-url $RPC --private-key $PRIVATE_KEY

# Update signer (rotate backend wallet)
cast send $VAULT "setSigner(address)" 0xNEW_SIGNER \
  --rpc-url $RPC --private-key $PRIVATE_KEY

# Rescue funds (emergency withdrawal)
cast send $VAULT "rescueFunds(address,uint256)" 0xTOKEN 1000000 \
  --rpc-url $RPC --private-key $PRIVATE_KEY

# Read campaign token
cast call $VAULT "campaignTokens(uint256)" 1 --rpc-url $RPC

# Check if user claimed
cast call $VAULT "hasClaimed(uint256,address)" 1 0xUSER --rpc-url $RPC
```

### Using Viem (TypeScript)

```typescript
import { createWalletClient, createPublicClient, http, parseAbi } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { base } from 'viem/chains';

const VAULT_ADDRESS = '0xYourVaultAddress';
const VAULT_ABI = parseAbi([
  'function setupCampaign(uint256 id, address token) external',
  'function updateCampaignToken(uint256 id, address newToken) external',
  'function pauseCampaign(uint256 id) external',
  'function setSigner(address newSigner) external',
  'function rescueFunds(address token, uint256 amount) external',
  'function campaignTokens(uint256 id) view returns (address)',
  'function hasClaimed(uint256 campaignId, address user) view returns (bool)',
]);

const account = privateKeyToAccount(process.env.PRIVATE_KEY as `0x${string}`);
const walletClient = createWalletClient({
  account,
  chain: base,
  transport: http(),
});

// Setup a new campaign
async function setupCampaign(campaignId: bigint, tokenAddress: `0x${string}`) {
  const hash = await walletClient.writeContract({
    address: VAULT_ADDRESS,
    abi: VAULT_ABI,
    functionName: 'setupCampaign',
    args: [campaignId, tokenAddress],
  });
  console.log('Campaign created:', hash);
}

// Fund the vault (setupCampaign only registers the token - you must fund separately)
async function fundVault(tokenAddress: `0x${string}`, amount: bigint) {
  const hash = await walletClient.writeContract({
    address: tokenAddress,
    abi: parseAbi(['function transfer(address,uint256) returns (bool)']),
    functionName: 'transfer',
    args: [VAULT_ADDRESS, amount],
  });
  console.log('Vault funded:', hash);
}

// Update campaign token
async function updateCampaignToken(campaignId: bigint, newToken: `0x${string}`) {
  const hash = await walletClient.writeContract({
    address: VAULT_ADDRESS,
    abi: VAULT_ABI,
    functionName: 'updateCampaignToken',
    args: [campaignId, newToken],
  });
  console.log('Campaign updated:', hash);
}

// Pause campaign
async function pauseCampaign(campaignId: bigint) {
  const hash = await walletClient.writeContract({
    address: VAULT_ADDRESS,
    abi: VAULT_ABI,
    functionName: 'pauseCampaign',
    args: [campaignId],
  });
  console.log('Campaign paused:', hash);
}

// Example usage
const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
await setupCampaign(1n, USDC_BASE);
await fundVault(USDC_BASE, 10000000000n); // 10,000 USDC (6 decimals)
```

---

## Backend Integration

The backend is responsible for:
1. Tracking user actions and calculating rewards
2. Storing claim eligibility in a database
3. Generating EIP-712 signatures on demand when users request to claim

### Signature Generation (Viem)

```typescript
import { privateKeyToAccount } from 'viem/accounts';

// Backend signer (HOT WALLET - keep secure!)
const SIGNER_PRIVATE_KEY = process.env.SIGNER_PRIVATE_KEY as `0x${string}`;
const signerAccount = privateKeyToAccount(SIGNER_PRIVATE_KEY);

// Contract address
const VAULT_ADDRESS = '0xYourVaultAddress' as const;
const CHAIN_ID = 8453; // Base

// EIP-712 Domain
const domain = {
  name: 'QuotientLeaderboardVault',
  version: '1',
  chainId: CHAIN_ID,
  verifyingContract: VAULT_ADDRESS,
} as const;

// EIP-712 Types
const types = {
  Claim: [
    { name: 'campaignId', type: 'uint256' },
    { name: 'claimant', type: 'address' },
    { name: 'amount', type: 'uint256' },
  ],
} as const;

// Generate signature for a claim
async function generateClaimSignature(
  campaignId: bigint,
  claimant: `0x${string}`,
  amount: bigint
): Promise<`0x${string}`> {
  const signature = await signerAccount.signTypedData({
    domain,
    types,
    primaryType: 'Claim',
    message: {
      campaignId,
      claimant,
      amount,
    },
  });

  return signature;
}

// Example API endpoint handler
async function handleClaimRequest(req: Request) {
  const { campaignId, userAddress } = await req.json();

  // 1. Check database: Is user eligible?
  const eligibility = await db.getEligibility(campaignId, userAddress);
  if (!eligibility) {
    return new Response('Not eligible', { status: 403 });
  }

  // 2. Check database: Has user already been issued a signature?
  //    (Optional - contract handles double-claim, but saves gas to check here)
  const alreadyClaimed = await db.hasClaimedSignature(campaignId, userAddress);
  if (alreadyClaimed) {
    return new Response('Already claimed', { status: 400 });
  }

  // 3. Generate signature
  const signature = await generateClaimSignature(
    BigInt(campaignId),
    userAddress as `0x${string}`,
    eligibility.amount
  );

  // 4. Mark as signature issued (optional tracking)
  await db.markSignatureIssued(campaignId, userAddress);

  // 5. Return signature to frontend
  return Response.json({
    campaignId,
    amount: eligibility.amount.toString(),
    signature,
  });
}
```

---

## Frontend Integration

### Claiming Rewards (Viem)

```typescript
import { createWalletClient, createPublicClient, custom, parseAbi } from 'viem';
import { base } from 'viem/chains';

const VAULT_ADDRESS = '0xYourVaultAddress';
const VAULT_ABI = parseAbi([
  'function claim(uint256 campaignId, uint256 amount, bytes signature) external',
  'function hasClaimed(uint256 campaignId, address user) view returns (bool)',
  'event Payout(uint256 indexed campaignId, address indexed claimant, uint256 amount)',
]);

// Connect to user's wallet
const walletClient = createWalletClient({
  chain: base,
  transport: custom(window.ethereum),
});

const publicClient = createPublicClient({
  chain: base,
  transport: custom(window.ethereum),
});

async function claimReward(campaignId: number) {
  const [address] = await walletClient.getAddresses();

  // 1. Check if already claimed (optional - saves gas on failed tx)
  const alreadyClaimed = await publicClient.readContract({
    address: VAULT_ADDRESS,
    abi: VAULT_ABI,
    functionName: 'hasClaimed',
    args: [BigInt(campaignId), address],
  });

  if (alreadyClaimed) {
    throw new Error('Already claimed');
  }

  // 2. Request signature from backend
  const response = await fetch('/api/claim', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ campaignId, userAddress: address }),
  });

  if (!response.ok) {
    throw new Error('Not eligible or already claimed');
  }

  const { amount, signature } = await response.json();

  // 3. Submit claim transaction
  const hash = await walletClient.writeContract({
    address: VAULT_ADDRESS,
    abi: VAULT_ABI,
    functionName: 'claim',
    args: [BigInt(campaignId), BigInt(amount), signature as `0x${string}`],
  });

  // 4. Wait for confirmation
  const receipt = await publicClient.waitForTransactionReceipt({ hash });

  console.log('Claimed successfully!', receipt);
  return receipt;
}
```

---

## Contract Reference

### State Variables

| Name | Type | Description |
|------|------|-------------|
| `signer` | `address` | Backend hot wallet that signs claims |
| `campaignTokens` | `mapping(uint256 => address)` | Campaign ID → ERC-20 token |
| `hasClaimed` | `mapping(uint256 => mapping(address => bool))` | Tracks claims |

### Functions

| Function | Access | Description |
|----------|--------|-------------|
| `setupCampaign(id, token)` | Owner | Create a new campaign |
| `updateCampaignToken(id, newToken)` | Owner | Change campaign's token |
| `pauseCampaign(id)` | Owner | Disable claims for campaign |
| `setSigner(newSigner)` | Owner | Rotate backend signer |
| `rescueFunds(token, amount)` | Owner | Emergency withdrawal |
| `claim(campaignId, amount, signature)` | Anyone | Claim rewards with valid signature |
| `DOMAIN_SEPARATOR()` | View | EIP-712 domain separator |
| `getClaimDigest(campaignId, claimant, amount)` | View | Compute digest for signing |

### Events

| Event | Parameters | Description |
|-------|------------|-------------|
| `CampaignSetup` | `campaignId, token` | New campaign created |
| `CampaignUpdated` | `campaignId, oldToken, newToken` | Campaign token changed |
| `CampaignPaused` | `campaignId` | Campaign disabled |
| `Payout` | `campaignId, claimant, amount` | Reward claimed |
| `SignerUpdated` | `newSigner` | Signer rotated |

### Errors

| Error | Cause |
|-------|-------|
| `AlreadyClaimed` | User already claimed this campaign |
| `CampaignNotActive` | Campaign doesn't exist or is paused |
| `CampaignAlreadyExists` | Campaign ID already in use |
| `CampaignNotFound` | Campaign doesn't exist (for update/pause) |
| `InvalidSignature` | Signature doesn't match signer |
| `InvalidSigner` | Signer address is zero |
| `InvalidAmount` | Claim amount is zero |
| `InvalidToken` | Token address is zero |

---

## Security Considerations

1. **Signer Key Security**: The backend signer private key is a hot wallet. If compromised, attacker can drain the vault. Use HSM or KMS in production.

2. **Campaign Token Updates**: Updating a campaign's token is dangerous. Existing signatures will transfer the NEW token. Only do this if no signatures are pending.

3. **No Signature Expiry**: Signatures never expire. The backend should track issued signatures and the `hasClaimed` mapping prevents replay.

4. **EIP-712 Protection**: Signatures are chain-specific and contract-specific. They cannot be replayed on other chains or contracts.

---

## Testing

```bash
# Run all tests
forge test

# Run with verbosity
forge test -vvv

# Run specific test
forge test --match-test test_Claim_Success

# Gas report
forge test --gas-report

# Coverage
forge coverage
```

---

## License

MIT
