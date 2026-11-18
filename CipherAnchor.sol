// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title CipherAnchor
 * @notice Optional on-chain provenance for CipherLoom (hackathon 2349 bonus track).
 *
 * A user commits `sha256(cid || ciphertext_digest)` when a document is encrypted.
 * Because only the hash goes on-chain, the vault payload stays private; anyone
 * holding the file can later prove it existed unchanged at commit time
 * (tamper-evident audit trail for regulated/sustainability data use-cases).
 *
 * Deploy to any EVM L2 (Base/Arbitrum/Optimism — cheap calldata) or wrap with
 * a Solana/Rust program later using the same commitment scheme.
 */
contract CipherAnchor {
    struct Anchor {
        address owner;
        uint64  timestamp;
        string  tag;          // e.g. "ipfs:bafycipher..." or doc label
    }

    /// commitment (bytes32) -> Anchor
    mapping(bytes32 => Anchor) public anchors;

    event Anchored(bytes32 indexed commitment, address indexed owner, string tag, uint64 timestamp);
    event Disputed(bytes32 indexed commitment, address indexed owner);

    error AlreadyCommitted(bytes32 commitment);
    error EmptyCommitment();

    /// @notice Anchor a commitment once. Idempotency is enforced per-commitment.
    function commit(bytes32 commitment, string calldata tag) external {
        if (commitment == bytes32(0)) revert EmptyCommitment();
        if (anchors[commitment].timestamp != 0) revert AlreadyCommitted(commitment);
        anchors[commitment] = Anchor({
            owner: msg.sender,
            timestamp: uint64(block.timestamp),
            tag: tag
        });
        emit Anchored(commitment, msg.sender, tag, uint64(block.timestamp));
    }

    /// @notice Verify a commitment exists and has not moved (storage is immutable per key).
    function verify(bytes32 commitment) external view returns (bool exists, address owner, uint64 ts) {
        Anchor storage a = anchors[commitment];
        return (a.timestamp != 0, a.owner, a.timestamp);
    }

    /// @notice Owner can flag their own anchor as disputed (e.g. key compromise notice).
    function dispute(bytes32 commitment) external {
        require(anchors[commitment].owner == msg.sender, "not owner");
        emit Disputed(commitment, msg.sender);
    }
}