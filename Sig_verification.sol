// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/* Signature Verification

How to Sign and Verify
1. hash(message) 
2. ethHash(message)
3. split Signature in v,r,s
4. ecrecover( ethHash(massage),signature)==signer

*/


contract VerifySig {

    function Verify(address _signer, string memory _message, bytes memory _sig)
    external pure returns(bool){
        bytes32 messageHash = getMessageHash(_message);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        return recoverSigner(ethSignedMessageHash,_sig) ==  _signer;     
    } 

    function getMessageHash(string memory _message) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_message));
    }

    function getEthSignedMessageHash(bytes32 _messageHash) 
    public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", _messageHash));
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _sig)
    public pure returns (address)
    {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_sig);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig)
    public pure returns (bytes32 r, bytes32 s, uint8 v)
    {
        require(sig.length == 65, "invalid signature length");

        assembly {
            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

    }
}

