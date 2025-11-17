// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {MessageHashUtils} from "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "lib/account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract MinimalAccount is IAccount, Ownable {
    /*///////////////////////////////////////////////////////////////
    /////////////             Errors              ///////////////////
    ///////////////////////////////////////////////////////////////*/

    error MinimalAccount__NotFromEntryPoint();
    error MinimalAccount__NotFromEntryPointOrOwner();
    error MinimalAccount__CallFailed(bytes result);

    /*///////////////////////////////////////////////////////////////
    /////////////       State Variables           ///////////////////
    ///////////////////////////////////////////////////////////////*/

    IEntryPoint private immutable i_entryPoint;

    /*///////////////////////////////////////////////////////////////
    /////////////             Modifiers              ////////////////
    ///////////////////////////////////////////////////////////////*/

    modifier requireFromEntryPoint() {
        if (msg.sender != address(i_entryPoint)) {
            revert MinimalAccount__NotFromEntryPoint();
        }
        _;
    }

    modifier requireFromEntryPointOrOwner() {
        if (msg.sender != address(i_entryPoint) && msg.sender != owner()) {
            revert MinimalAccount__NotFromEntryPointOrOwner();
        }
        _;
    }

    /*///////////////////////////////////////////////////////////////
    /////////////             Functions              ////////////////
    ///////////////////////////////////////////////////////////////*/

    constructor(address entryPoint) Ownable(msg.sender) {
        i_entryPoint = IEntryPoint(entryPoint);
    }

    receive() external payable {}

    /*///////////////////////////////////////////////////////////////
    /////////////        External Functions             /////////////
    ///////////////////////////////////////////////////////////////*/

    // the execute function can be called by the entry point or the owner
    // this allows the owner to make direct calls to interact with DApps (AAVE, etc)

    /**
     * @dev Executes a call to a specified destination address with given value and function data.
     * @notice This function can only be called by the EntryPoint contract or the owner of the account.
     * @param dest The address of the contract to call.
     * @param value The amount of Ether (in wei) to send with the call.
     * @param functionData The calldata for the function to be executed on the destination contract.
     */

    function execute(address dest, uint256 value, bytes calldata functionData) external requireFromEntryPointOrOwner {
        (bool success, bytes memory result) = dest.call{value: value}(functionData);
        if (!success) {
            revert MinimalAccount__CallFailed(result);
        }
    }

    // This function is grabbed from IAccount.sol --> This is the MOST important thing!!!
    // A signature is valid, if its the Minimal Account owner
    // This should be setup to be ONLY CALLABLE by the entry point contract
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        requireFromEntryPoint
        returns (uint256 validationData)
    {
        validationData = _validateSignature(userOp, userOpHash);
        _payPrefund(missingAccountFunds); // this is how much we pay back to the entry point
        // we should also track and validate the nonce...ideally
        // _validateNonce()
    }

    /*///////////////////////////////////////////////////////////////
    /////////////        Internal Functions             /////////////
    ///////////////////////////////////////////////////////////////*/

    // EIP-191 version of the signed hash
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        returns (uint256 validationData)
    {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ECDSA.recover(ethSignedMessageHash, userOp.signature);
        if (signer != owner()) {
            return SIG_VALIDATION_FAILED;
        } // verify signature is the owner...
        return SIG_VALIDATION_SUCCESS;
    }

    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds > 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds, gas: type(uint256).max}("");
            (success);
        }
    }

    /*///////////////////////////////////////////////////////////////
    ////////////////        GETTERS             /////////////////////
    ///////////////////////////////////////////////////////////////*/

    function getEntryPoint() external view returns (address) {
        return address(i_entryPoint);
    }
}
