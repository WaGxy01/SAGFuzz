// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract FancyBank{
  mapping(address => uint256) private balances;
  uint256 dueDate = 0;
  uint256 unlock = 0;
  event WithdrawalFailed(address user, uint256 amount);
  
  function deposit(uint256 amount) public payable{
    require(msg.value >= amount);
    balances[msg.sender] += amount;
  }
  
  function setState(uint256 time, uint256 State) public{
    dueDate = time;
    unlock = State;
  }
  
  function withdraw(uint256 amount) public {
    require(balances[msg.sender] >= amount);
    if(dueDate > 30 && dueDate < 40 && unlock == 1){
      (bool success, ) = msg.sender.call{value: amount}("");
      require(success);
      balances[msg.sender] -= amount;
    } else {
      emit WithdrawalFailed(msg.sender, amount);
    }
  }

}