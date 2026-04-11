// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract FancyBank{
  mapping(address => uint256) private balances;
  uint256 dueDate = 0;
  uint256 unlock = 0;
  event WithdrawalFailed(address user, uint256 amount);
  uint256 public value;
  
  // view：只读状态，不可修改
  function getValue() public view returns (uint256) {
  	return value;
    }

    // pure：不读写状态，纯计算
  function add(uint256 a, uint256 b) public pure returns (uint256) {
	return a + b;
    }
  
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
