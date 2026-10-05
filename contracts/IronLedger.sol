// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IronLedger - Immutable ICS/SCADA Forensic Evidence Layer
 * @author IronLedger Security Core (Simran & Garima)
 * @notice Deployed on Ethereum Sepolia / Remix IDE for anchoring SCADA commands & sensor events.
 */
contract IronLedger {
    address public owner;
    uint256 public totalEvents;

    struct ICSEvent {
        uint256 eventId;
        bytes32 eventHash;       // SHA-256 / keccak256 fingerprint of event data
        bytes32 previousHash;    // Cryptographic link to previous block event
        uint256 timestamp;       // Block timestamp
        string source;           // e.g. "HMI-01", "SCADA-RTU-04", "SYS-ENG"
        string commandType;      // e.g. "SET_VALVE", "OVERRIDE_SIS", "PUMP_RPM"
        string entityId;         // e.g. "PUMP_A", "VALVE_VENT_01", "REACTOR_TEMP"
        address recordedBy;      // Signer wallet address
    }

    // Mapping from event ID to on-chain event record
    mapping(uint256 => ICSEvent) public events;
    // Mapping from event hash to event ID
    mapping(bytes32 => uint256) public hashToEventId;

    event EventAnchored(
        uint256 indexed eventId,
        bytes32 indexed eventHash,
        uint256 timestamp,
        string source,
        string commandType,
        string entityId,
        address indexed recordedBy
    );

    event TamperAlert(
        uint256 indexed eventId,
        bytes32 expectedHash,
        bytes32 submittedHash,
        address indexed reporter
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Only contract owner can execute this");
        _;
    }

    constructor() {
        owner = msg.sender;
        totalEvents = 0;
    }

    /**
     * @notice Records an ICS command or telemetry state hash onto the immutable ledger.
     */
    function recordEvent(
        bytes32 _eventHash,
        bytes32 _previousHash,
        string calldata _source,
        string calldata _commandType,
        string calldata _entityId
    ) external returns (uint256) {
        require(_eventHash != bytes32(0), "Invalid event hash");

        totalEvents++;
        uint256 newId = totalEvents;

        events[newId] = ICSEvent({
            eventId: newId,
            eventHash: _eventHash,
            previousHash: _previousHash,
            timestamp: block.timestamp,
            source: _source,
            commandType: _commandType,
            entityId: _entityId,
            recordedBy: msg.sender
        });

        hashToEventId[_eventHash] = newId;

        emit EventAnchored(
            newId,
            _eventHash,
            block.timestamp,
            _source,
            _commandType,
            _entityId,
            msg.sender
        );

        return newId;
    }

    /**
     * @notice Verifies whether a submitted event metadata hash matches the immutable on-chain record.
     * @param _eventId ID of the event to verify
     * @param _submittedHash Hash computed from the off-chain database (e.g. Supabase)
     * @return isValid True if match, false if database record was tampered with!
     * @return storedHash The authentic on-chain hash
     * @return blockTimestamp The timestamp when the block was minted
     */
    function verifyHash(uint256 _eventId, bytes32 _submittedHash)
        external
        view
        returns (bool isValid, bytes32 storedHash, uint256 blockTimestamp)
    {
        require(_eventId > 0 && _eventId <= totalEvents, "Event does not exist");
        ICSEvent memory ev = events[_eventId];
        return (ev.eventHash == _submittedHash, ev.eventHash, ev.timestamp);
    }

    /**
     * @notice Fetch an event by ID for forensic reconstruction.
     */
    function getEvent(uint256 _eventId) external view returns (ICSEvent memory) {
        require(_eventId > 0 && _eventId <= totalEvents, "Event does not exist");
        return events[_eventId];
    }
}
