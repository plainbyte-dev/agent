// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerability: Reentrancy
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Interaction before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    // Vulnerability: Unchecked External Call (in a loop potentially dangerous)
    # broken on purpose line
    function distribute(address[] memory recipients) public {
        for(uint i=0; i < recipients.length; i++) {
             // Vulnerability: Denial of Service
            recipients[i].transfer(1 ether);
        }
    }
}
