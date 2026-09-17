<?php
if (!defined('FLUX_ROOT')) exit;

require_once 'Flux/Recovery.php';

$title = Flux::message('AccountConfirmTitle');
$token = $params->get('token');
$login = $params->get('login');

if (!$login || !($loginAthenaGroup = Flux::getServerGroupByName($login))) {
	$this->deny();
}

$recovery = new Flux_Recovery($loginAthenaGroup);
$pending = $recovery->find($token, Flux_Recovery::PURPOSE_CONFIRM);
if (!$pending) {
	$this->deny();
}

$createTable = Flux::config('FluxTables.AccountCreateTable');
$tokenHash = Flux_Recovery::hashToken($token);
$sql = "UPDATE {$loginAthenaGroup->loginDatabase}.{$createTable} SET ";
$sql .= "confirmed = 1, confirm_code = NULL, confirm_expire = NULL ";
$sql .= "WHERE account_id = ? AND confirm_code = ? AND confirmed = 0";
$sth = $loginAthenaGroup->connection->getStatement($sql);
if (!$sth->execute(array($pending->account_id, $tokenHash)) || $sth->rowCount() !== 1) {
	$this->deny();
}

$remoteAddress = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
if (!$recovery->consume($pending->id, $remoteAddress)) {
	$this->deny();
}

$sql = "UPDATE {$loginAthenaGroup->loginDatabase}.login SET state = 0, unban_time = 0 WHERE account_id = ?";
$sth = $loginAthenaGroup->connection->getStatement($sql);
$sth->execute(array($pending->account_id));

$session->setMessageData(Flux::message('AccountConfirmMessage'));
$this->redirect($this->url('account', 'login'));
?>
