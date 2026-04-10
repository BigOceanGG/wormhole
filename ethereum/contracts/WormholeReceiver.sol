// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IWormhole {
    struct Signature {
        bytes32 r;
        bytes32 s;
        uint8 v;
        uint8 guardianIndex;
    }
    struct VM {
        uint8 version;
        uint32 timestamp;
        uint32 nonce;
        uint16 emitterChainId;
        bytes32 emitterAddress;
        uint64 sequence;
        uint8 consistencyLevel;
        bytes payload;
        uint32 guardianSetIndex;
        Signature[] signatures;
        bytes32 hash;
    }
    function parseAndVerifyVM(bytes calldata encodedVM)
        external view returns (VM memory vm, bool valid, string memory reason);
}

contract WormholeReceiver {
    IWormhole public wormhole;
    mapping(bytes32 => bool) public processedMessages;

    event MessageReceived(
        uint16 emitterChainId,
        bytes32 emitterAddress,
        uint64 sequence,
        bytes payload
    );

    constructor(address wormholeCore) {
        wormhole = IWormhole(wormholeCore);
    }

    function receiveMessage(bytes memory encodedVM) external {
        (IWormhole.VM memory vm, bool valid, string memory reason) =
            wormhole.parseAndVerifyVM(encodedVM);
        require(valid, reason);

        require(!processedMessages[vm.hash], "already processed");
        processedMessages[vm.hash] = true;

        emit MessageReceived(
            vm.emitterChainId,
            vm.emitterAddress,
            vm.sequence,
            vm.payload
        );
    }
}
