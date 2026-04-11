// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract GambleNum {
    // 状态变量
    uint256 start = now;
    uint256 end = now + 7 days;
    
    address public sponsor;                              // 赞助者/发起人
    uint256 public targetNumber;                         // 目标数字
    uint256 public bonusPool;                            // 奖金池
    mapping(address => uint256) public userGuesses;      // 用户猜测记录
    mapping(address => uint256) public userBalance;      // 用户余额记录

    // 构造函数，部署者即为sponsor
    constructor() public {
        sponsor = msg.sender;
    }

    // 设置目标数字，仅sponsor可调用
    function SetTarget(uint256 _target) public {
        if (msg.sender == sponsor) {
            targetNumber = _target;
        }
    }

    // 参与猜数游戏，需支付10 finney
    function Participate(uint256 guess) payable public {
        require(now < end);
        userGuesses[msg.sender] = guess;
        bonusPool += msg.value;
        if (userGuesses[msg.sender] == targetNumber && msg.value == 10 finney) {
            userBalance[msg.sender] = bonusPool / 2;  // 存在重入漏洞
        }
    }

    // 提取奖励（存在重入漏洞：先转账后清零）
    function Withdraw() payable public {
        require(now < end);
        if (userBalance[msg.sender] > 0) {
            msg.sender.call.value(userBalance[msg.sender])();  // ① 先转账
            userBalance[msg.sender] = 0;                        // ② 后清零 → 重入漏洞
        }
    }
}
