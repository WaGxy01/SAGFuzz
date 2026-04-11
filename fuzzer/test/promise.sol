pragma solidity ^0.4.26;
contract Promise {
    string vow; address promisor;
    bool sentMoney; uint public deposit;
    uint public foulVotes;
    address public beneficiary;
    address[3] public judges;
    uint[3] public signedByJudge;
    //mapping(uint => uint) signedByJudge;
    uint[3] public votedFoul;
    uint a;

    constructor (string _vow, uint _deposit, address[3] _judges, address _beneficiary) public payable{
        vow = _vow; deposit = _deposit;
        require(msg.value >= deposit);
        judges = _judges; promisor = msg.sender;
        beneficiary = _beneficiary;    }
    function judgeSigns(uint _number) public{
        require(msg.sender == judges[_number]);
        signedByJudge[_number] = 1;    }
    function voteFoul(uint _number) public{
        require(signedByJudge[0] == 1);
        require(signedByJudge[1] == 1);
        require(signedByJudge[2] == 1);
        require(msg.sender == judges[_number]);
        require(votedFoul[_number] != 1);
        foulVotes = foulVotes + 1;
        votedFoul[_number] = 1;    }

    function sent() public{
        require(foulVotes >= 2);
        require(!sentMoney);
        beneficiary.transfer(deposit);
        sentMoney = true;
        if (votedFoul[0]!=1){
            assert(false);
        }}
    function selfDestruct() public{
      require(sentMoney);
      selfdestruct(msg.sender);    }}
