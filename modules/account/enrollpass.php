<?php
if (!defined('FLUX_ROOT')) exit;

$this->loginRequired();

$title = 'Next-Login Password Recovery';
$accountID = (int)$params->get('id');

if (!$server->loginServer->password->usesPasswordEnrollment()) {
	$this->deny();
}

$sql = "SELECT account_id, userid, group_id, passwd_type FROM {$server->loginDatabase}.login ";
$sql .= "WHERE account_id = ? AND sex IN ('M', 'F') LIMIT 1";
$sth = $server->connection->getStatement($sql);
$sth->execute(array($accountID));
$account = $sth->fetch();

if (!$account) {
	$this->deny();
}

$accountLevel = AccountLevel::getGroupLevel($account->group_id);
if ($accountLevel > $session->account->group_level && !$auth->allowedToEditHigherPower) {
	$this->deny();
}

$recoveryPending = ((int)$account->passwd_type & Flux_Password::FLAG_ENROLL) !== 0;

if (count($_POST)) {
	if ($params->get('activate')) {
		$sql = "UPDATE {$server->loginDatabase}.login SET passwd_type = passwd_type | ? WHERE account_id = ?";
		$bind = array(Flux_Password::FLAG_ENROLL, $account->account_id);
		$message = "Next-login password recovery activated for {$account->userid}.";
	}
	elseif ($params->get('cancel')) {
		$sql = "UPDATE {$server->loginDatabase}.login SET passwd_type = passwd_type & ? WHERE account_id = ?";
		$bind = array(0xff ^ Flux_Password::FLAG_ENROLL, $account->account_id);
		$message = "Next-login password recovery cancelled for {$account->userid}.";
	}
	else {
		$this->deny();
	}

	$sth = $server->connection->getStatement($sql);
	if (!$sth->execute($bind)) {
		throw new RuntimeException('Failed to update password recovery state.');
	}

	$session->setMessageData($message);
	$this->redirect($this->url('account', 'view', array('id' => $account->account_id)));
}
?>
