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

import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.9.3/contracts/token/ERC20/ERC20.sol";

contract BridgeToken is ERC20 {
    IWormhole public wormhole;
    mapping(bytes32 => bool) public processedMessages;

    constructor(address wormholeCore) ERC20("Bridge Token", "BT") {
        wormhole = IWormhole(wormholeCore);
    }

    function receiveMessage(bytes memory encodedVM) external {
        (IWormhole.VM memory vm, bool valid, string memory reason) =
                            wormhole.parseAndVerifyVM(encodedVM);
        require(valid, reason);

        require(!processedMessages[vm.hash], "already processed");
        processedMessages[vm.hash] = true;

        // 解析 payload
        (address recipient, uint256 amount) = abi.decode(vm.payload, (address, uint256));

        // mint 到目标地址
        _mint(recipient, amount);
    }
}
