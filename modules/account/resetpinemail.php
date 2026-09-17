<?php
if (!defined('FLUX_ROOT')) exit;

if (!Flux::config('PincodeEnabled')) {
	$this->deny();
}

require_once 'Flux/Recovery.php';

$title = 'Confirm PIN Reset';
$token = $params->get('token');
$login = $params->get('login');
$loginAthenaGroup = Flux::getServerGroupByName($login);
if (!$loginAthenaGroup) {
	$this->deny();
}

$recovery = new Flux_Recovery($loginAthenaGroup);
$account = $recovery->find($token, Flux_Recovery::PURPOSE_PIN);
if (!$account || AccountLevel::getGroupLevel($account->group_id) >= Flux::config('NoResetPassGroupLevel')) {
	$this->deny();
}

if (count($_POST)) {
	if (!$params->get('reset')) {
		$this->deny();
	}
	$remoteAddress = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
	if (!$recovery->consume($account->id, $remoteAddress)) {
		$this->deny();
	}

	$sql = "UPDATE {$loginAthenaGroup->loginDatabase}.login SET pincode = '', pincode_change = 0 ";
	$sql .= "WHERE account_id = ? AND state = 0 AND sex IN ('M', 'F')";
	$sth = $loginAthenaGroup->connection->getStatement($sql);
	if (!$sth->execute(array($account->account_id))) {
		throw new RuntimeException('Failed to reset account PIN.');
	}

	$session->setMessageData('PIN reset. Create a new PIN at the next game login.');
	$this->redirect($this->url('account', 'login'));
}
?>
