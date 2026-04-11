// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

interface IHelper {
    function beforeWithdraw(address user, uint256 amount) external;
}

contract VulnerableBank {

    mapping(address => uint256) public balances;
    address public helper;

    constructor(address _helper) {
        helper = _helper;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        
        IHelper(helper).beforeWithdraw(msg.sender, amount);

        
        balances[msg.sender] = 0;

        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}