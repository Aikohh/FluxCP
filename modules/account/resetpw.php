<?php
if (!defined('FLUX_ROOT')) exit;

require_once 'Flux/Recovery.php';

$title = 'Choose New Password';
$token = $params->get('token');
$login = $params->get('login');
$loginAthenaGroup = Flux::getServerGroupByName($login);
if (!$loginAthenaGroup) {
	$this->deny();
}

$recovery = new Flux_Recovery($loginAthenaGroup);
$account = $recovery->find($token, Flux_Recovery::PURPOSE_PASSWORD);
if (!$account || AccountLevel::getGroupLevel($account->group_id) >= Flux::config('NoResetPassGroupLevel')) {
	$this->deny();
}

if (count($_POST)) {
	$password = (string)$params->get('password');
	$confirm = (string)$params->get('confirm_password');

	if (!ctype_graph($password)) {
		$errorMessage = Flux::message('InvalidPassword');
	}
	elseif (strlen($password) < Flux::config('MinPasswordLength')) {
		$errorMessage = sprintf(Flux::message('PasswordTooShort'), Flux::config('MinPasswordLength'), Flux::config('MaxPasswordLength'));
	}
	elseif (strlen($password) > Flux::config('MaxPasswordLength')) {
		$errorMessage = sprintf(Flux::message('PasswordTooLong'), Flux::config('MinPasswordLength'), Flux::config('MaxPasswordLength'));
	}
	elseif ($password !== $confirm) {
		$errorMessage = Flux::message('PasswordsDoNotMatch');
	}
	elseif (!Flux::config('AllowUserInPassword') && stripos($password, $account->userid) !== false) {
		$errorMessage = Flux::message('PasswordHasUsername');
	}
	elseif (Flux::config('PasswordMinUpper') > 0 && preg_match_all('/[A-Z]/', $password, $matches) < Flux::config('PasswordMinUpper')) {
		$errorMessage = sprintf(Flux::message('PasswordNeedUpper'), Flux::config('PasswordMinUpper'));
	}
	elseif (Flux::config('PasswordMinLower') > 0 && preg_match_all('/[a-z]/', $password, $matches) < Flux::config('PasswordMinLower')) {
		$errorMessage = sprintf(Flux::message('PasswordNeedLower'), Flux::config('PasswordMinLower'));
	}
	elseif (Flux::config('PasswordMinNumber') > 0 && preg_match_all('/[0-9]/', $password, $matches) < Flux::config('PasswordMinNumber')) {
		$errorMessage = sprintf(Flux::message('PasswordNeedNumber'), Flux::config('PasswordMinNumber'));
	}
	elseif (Flux::config('PasswordMinSymbol') > 0 && preg_match_all('/[^A-Za-z0-9]/', $password, $matches) < Flux::config('PasswordMinSymbol')) {
		$errorMessage = sprintf(Flux::message('PasswordNeedSymbol'), Flux::config('PasswordMinSymbol'));
	}
	else {
		$remoteAddress = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
		if (!$recovery->consume($account->id, $remoteAddress)) {
			$this->deny();
		}

		list($hash, $type) = $loginAthenaGroup->loginServer->password->hash($password);
		$sql = "UPDATE {$loginAthenaGroup->loginDatabase}.login SET user_pass = ?, passwd_type = ? ";
		$sql .= "WHERE account_id = ? AND state = 0 AND sex IN ('M', 'F')";
		$sth = $loginAthenaGroup->connection->getStatement($sql);
		if (!$sth->execute(array($hash, $type, $account->account_id))) {
			throw new RuntimeException('Failed to update account password.');
		}

		$session->setMessageData('Password changed. You may now log in.');
		$this->redirect($this->url('account', 'login'));
	}
}
?>
