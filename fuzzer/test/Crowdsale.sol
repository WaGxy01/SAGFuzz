// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract Crowdsale {
    // State Variables
    uint256 phase = 0; // 0: Active, 1: Success
    uint256 goal;
    uint256 invested;
    address owner;
    mapping(address => uint256) invests;

    constructor()  {
        goal = 100 ether;
        invested = 0;
        owner = msg.sender;
    }

    function invest(uint256 donations) public payable {
        if (invested < goal) {
            invests[msg.sender] += donations;
            invested += donations;
            phase = 0;
        } else {
            phase = 1;
        }
    }

    function refund() public {
        if (phase == 0) {
            msg.sender.transfer(invests[msg.sender]);
            invests[msg.sender] = 0;
        }
    }

    function withdraw() public {
        require(msg.sender == owner, "Only owner can withdraw");
        require(phase == 1, "Crowdsale is still active");
    
        uint256 amount = invested;
        
    
        (bool success, ) = owner.call{value: amount}("");
        require(success, "Transfer failed");
        invested = 0; // 防止重入，先清零
}
}