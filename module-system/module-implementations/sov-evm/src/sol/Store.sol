// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract SimpleStorage {
    uint256 public num;
    
    function set(uint256 _num) public {
    //function set() public {
        num = _num;
    }
    
    function get() public view returns (uint) {
        return num;
    }
}