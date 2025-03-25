/**
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2023, Circle Internet Financial, LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

pragma solidity ^0.8.10;
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title Blacklistable Token
 * @dev Allows accounts to be restricted by a "restrictor" role
 */
abstract contract Restrictable is Ownable {
    address public restrictor;
    mapping(address => bool) internal _deprecatedRestricted;

    event Restricted(address indexed _account);
    event UnRestricted(address indexed _account);
    event RestrictorChanged(address indexed newRestrictor);

    /**
     * @dev Throws if called by any account other than the .
     */
    modifier onlyRestrictor() {
        require(msg.sender == restrictor, "ONLY_RESTRICTER");
        _;
    }

    /**
     * @dev Throws if argument account is restricted.
     * @param _account The address to check.
     */
    modifier notRestricted(address _account) {
        require(!_isRestricted(_account), "ACCOUNT_IS_RESTRICTED");
        _;
    }

    /**
     * @notice Checks if account is restricted.
     * @param _account The address to check.
     * @return True if the account is restricted, false if the account is not restricted.
     */
    function isRestricted(address _account) external view returns (bool) {
        return _isRestricted(_account);
    }

    /**
     * @notice Adds account to list.
     * @param _account The address to restrict.
     */
    function restrict(address _account) external onlyRestrictor {
        _restrict(_account);
        emit Restricted(_account);
    }

    /**
     * @notice Removes account from restrict list.
     * @param _account The address to remove from the restrict.
     */
    function unRestrict(address _account) external onlyRestrictor {
        _unRestrict(_account);
        emit UnRestricted(_account);
    }

    /**
     * @notice Updates the restrictor address.
     * @param _newRestrictor The address of the new restrictor.
     */
    function updateRestrictor(address _newRestrictor) external onlyOwner {
        require(_newRestrictor != address(0), "Blacklistable: new restrictor is the zero address");
        restrictor = _newRestrictor;
        emit RestrictorChanged(restrictor);
    }

    /**
     * @dev Checks if account is restricted.
     * @param _account The address to check.
     * @return true if the account is restricted, false otherwise.
     */
    function _isRestricted(address _account) internal view virtual returns (bool);

    /**
     * @dev Helper method that restrict list an account.
     * @param _account The address to restrict list.
     */
    function _restrict(address _account) internal virtual;

    /**
     * @dev Helper method that unrestrict an account.
     * @param _account The address should be remove.
     */
    function _unRestrict(address _account) internal virtual;
}
