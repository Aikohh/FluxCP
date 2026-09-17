<?php
if (!defined('FLUX_ROOT')) exit;

$this->loginRequired();

$title = Flux::message('EmailConfirmTitle');
$token = $params->get('token');
$login = $params->get('login');
$emailChangeTable = Flux::config('FluxTables.ChangeEmailTable');

if ($session->loginAthenaGroup->serverName !== $login || !preg_match('/^[a-f0-9]{64}$/D', $token)) {
	$this->deny();
}

$windowStart = date('Y-m-d H:i:s', time() - ((int)Flux::config('RecoveryTokenExpire') * 60));
$sql = "SELECT id, new_email FROM {$server->loginDatabase}.{$emailChangeTable} ";
$sql .= "WHERE code = ? AND account_id = ? AND request_date >= ? AND change_done = 0 LIMIT 1";
$sth = $server->connection->getStatement($sql);
$sth->execute(array(hash('sha256', $token), $session->account->account_id, $windowStart));
$change = $sth->fetch();
if (!$change) {
	$this->deny();
}

$sql = "SELECT account_id FROM {$server->loginDatabase}.login WHERE LOWER(email) = LOWER(?) ";
$sql .= "AND account_id != ? LIMIT 1";
$sth = $server->connection->getStatement($sql);
$sth->execute(array($change->new_email, $session->account->account_id));
if ($sth->fetch()) {
	$this->deny();
}

$remoteAddress = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
$sql = "UPDATE {$server->loginDatabase}.{$emailChangeTable} SET ";
$sql .= "change_date = NOW(), change_ip = ?, change_done = 1 WHERE id = ? AND change_done = 0";
$sth = $server->connection->getStatement($sql);
if (!$sth->execute(array($remoteAddress, $change->id)) || $sth->rowCount() !== 1) {
	$this->deny();
}

$sql = "UPDATE {$server->loginDatabase}.login SET email = ? WHERE account_id = ?";
$sth = $server->connection->getStatement($sql);
if (!$sth->execute(array($change->new_email, $session->account->account_id))) {
	throw new RuntimeException('Failed to update account email.');
}
$createTable = Flux::config('FluxTables.AccountCreateTable');
$sql = "UPDATE {$server->loginDatabase}.{$createTable} SET email = ? WHERE account_id = ?";
$sth = $server->connection->getStatement($sql);
$sth->execute(array($change->new_email, $session->account->account_id));
$session->account->email = $change->new_email;

$session->setMessageData(Flux::message('EmailConfirmChanged'));
$this->redirect($this->url('account', 'view'));
?>
