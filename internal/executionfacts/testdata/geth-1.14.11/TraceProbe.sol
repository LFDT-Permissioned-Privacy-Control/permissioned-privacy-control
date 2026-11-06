pragma solidity ^0.8.35;
contract Leaf {
    event Seen(address who, uint256 amount, address context);
    function sample() external payable returns (address, uint256, address) {
        return (msg.sender, msg.value, address(this));
    }
    function logged() external payable {
        emit Seen(msg.sender, msg.value, address(this));
    }
}
contract Failed {
    constructor(address target) payable {
        (bool ok,) = target.call(abi.encodeWithSignature("sample()"));
        require(ok);
        revert("constructor failed");
    }
}
contract Probe {
    function direct(address target) external payable {
        (bool ok,) = target.call{value: msg.value}(abi.encodeWithSignature("sample()"));
        require(ok);
    }
    function delegated(address target) external payable {
        (bool ok,) = target.delegatecall(abi.encodeWithSignature("sample()"));
        require(ok);
    }
    function coded(address target) external payable {
        bytes memory callData = abi.encodeWithSignature("sample()");
        assembly {
            if iszero(callcode(gas(), target, callvalue(), add(callData, 32), mload(callData), 0, 0)) { revert(0, 0) }
        }
    }
    function codedFixed(address target) external {
        bytes memory callData = abi.encodeWithSignature("sample()");
        assembly {
            if iszero(callcode(gas(), target, 7, add(callData, 32), mload(callData), 0, 0)) { revert(0, 0) }
        }
    }
    function staticCoded(address target) external payable {
        (bool ok,) = address(this).staticcall(abi.encodeWithSignature("codedFixed(address)", target));
        require(ok);
    }
    function caught(address target) external payable {
        try new Failed{value: msg.value}(target) returns (Failed) {} catch {}
    }
    function destroy(address payable beneficiary) external payable {
        selfdestruct(beneficiary);
    }
    function logged(address target) external payable {
        assembly { log0(0, 0) }
        (bool ok,) = target.call{value: msg.value}(abi.encodeWithSignature("logged()"));
        require(ok);
        assembly { log1(0, 0, 0x11) }
    }
}
