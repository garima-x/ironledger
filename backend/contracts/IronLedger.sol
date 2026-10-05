// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IronLedger
/// @notice Anchors a hash chain of ICS command/state commitments. The contract
/// never sees the underlying source/command/entity/params — only the SHA-256
/// commitment computed off-chain as H(source, command, entity, params, prevHash).
/// Because each anchor is bound to the previous one, an off-chain attempt to
/// alter or delete a historical record is detectable: recomputing the hash
/// from the (tampered) off-chain record will not match what was anchored here.
contract IronLedger {
    struct Anchor {
        bytes32 hash;
        bytes32 prevHash;
        uint256 timestamp;
        address submitter;
    }

    Anchor[] private anchors;
    bytes32 public latestHash;
    address public owner;

    event Anchored(
        uint256 indexed index,
        bytes32 hash,
        bytes32 prevHash,
        address indexed submitter,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "IronLedger: not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        latestHash = bytes32(0);
    }

    /// @notice Anchor a new hash, chained to the current tip.
    /// @param hash The SHA-256 commitment computed off-chain.
    /// @param expectedPrevHash Must equal `latestHash` at call time — this
    /// prevents a caller from anchoring against a stale or forged parent.
    function anchor(bytes32 hash, bytes32 expectedPrevHash) external onlyOwner returns (uint256 index) {
        require(expectedPrevHash == latestHash, "IronLedger: prevHash mismatch");
        index = anchors.length;
        anchors.push(Anchor({
            hash: hash,
            prevHash: expectedPrevHash,
            timestamp: block.timestamp,
            submitter: msg.sender
        }));
        latestHash = hash;
        emit Anchored(index, hash, expectedPrevHash, msg.sender, block.timestamp);
    }

    function getAnchor(uint256 index) external view returns (
        bytes32 hash, bytes32 prevHash, uint256 timestamp, address submitter
    ) {
        Anchor storage a = anchors[index];
        return (a.hash, a.prevHash, a.timestamp, a.submitter);
    }

    function count() external view returns (uint256) {
        return anchors.length;
    }
}
