// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import { ERC20Capped } from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Capped.sol";
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "../helpers/SafeTransferYul.sol";
import "../mixins/Restrictable.sol";

contract HoldToken is Ownable, ERC20Capped, ERC20Permit, AccessControl, Restrictable {
    uint public constant TOKEN_CAPPED = 30 * (10 ** 6) * (10 ** 18);
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    string public creator;

    constructor(address _owner) ERC20Capped(TOKEN_CAPPED) ERC20("Holdstation", "HOLD") ERC20Permit("Holdstation") {
        creator = "https://holdstation.com/";
        transferOwnership(_owner);
        _setupRole(DEFAULT_ADMIN_ROLE, _owner);
        restrictor = _owner;
    }

    modifier only(bytes32 role) {
        require(hasRole(role, msg.sender), "PERMISSION_DENIED");
        _;
    }

    function mint(address _account, uint256 _amount) external only(MINTER_ROLE) notRestricted(_account) {
        _mint(_account, _amount);
    }

    function _mint(address account, uint256 amount) internal override(ERC20, ERC20Capped) {
        super._mint(account, amount);
    }

    function transfer(
        address to,
        uint256 amount
    ) public override notRestricted(msg.sender) notRestricted(to) returns (bool) {
        return super.transfer(to, amount);
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public virtual override notRestricted(msg.sender) notRestricted(from) notRestricted(to) returns (bool) {
        return super.transferFrom(from, to, amount);
    }

    function approve(
        address spender,
        uint256 amount
    ) public override notRestricted(msg.sender) notRestricted(spender) returns (bool) {
        return super.approve(spender, amount);
    }

    function burn(uint256 _amount) external notRestricted(msg.sender) {
        _burn(msg.sender, _amount);
    }

    function claimStuckTokens(address _token) external onlyOwner {
        SafeTransferYul.safeTransferAll(_token, msg.sender);
    }

    /**
     * @inheritdoc Restrictable
     */
    function _restrict(address _account) internal override {
        _setRestrictionState(_account, true);
    }

    /**
     * @inheritdoc Restrictable
     */
    function _unRestrict(address _account) internal override {
        _setRestrictionState(_account, false);
    }

    /**
     * @dev A helper method that sets an account's restricted state.
     * @param _account         The address of the account.
     * @param _shouldRestrict True if the account should be restricted, false if the account should be unrestricted.
     */
    function _setRestrictionState(address _account, bool _shouldRestrict) internal virtual {
        _deprecatedRestricted[_account] = _shouldRestrict;
    }

    /**
     * @inheritdoc Restrictable
     */
    function _isRestricted(address _account) internal view virtual override returns (bool) {
        return _deprecatedRestricted[_account];
    }
}
