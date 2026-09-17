<?php
if (!defined('FLUX_ROOT')) exit;

$this->loginRequired();

if (!Flux::config('PincodeEnabled')) {
	$this->deny();
}

$title = 'Reset Player PIN';
$accountID = (int)$params->get('id');

$sql = "SELECT account_id, userid, group_id, pincode FROM {$server->loginDatabase}.login ";
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

$pinSet = (string)$account->pincode !== '';

if (count($_POST)) {
	if (!$params->get('reset')) {
		$this->deny();
	}

	$sql = "UPDATE {$server->loginDatabase}.login SET pincode = '', pincode_change = 0 WHERE account_id = ?";
	$sth = $server->connection->getStatement($sql);
	if (!$sth->execute(array($account->account_id))) {
		throw new RuntimeException('Failed to reset account PIN.');
	}

	if ($account->account_id == $session->account->account_id) {
		$session->account->pincode = '';
	}

	$remoteAddress = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
	error_log(sprintf(
		'FluxCP audit: PIN reset admin_account_id=%d target_account_id=%d remote_ip=%s',
		$session->account->account_id,
		$account->account_id,
		$remoteAddress
	));

	$session->setMessageData("PIN reset for {$account->userid}. The player must create a new PIN at the next game login.");
	$this->redirect($this->url('account', 'view', array('id' => $account->account_id)));
}
?>
