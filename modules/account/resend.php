<?php
if (!defined('FLUX_ROOT')) exit;

$title = Flux::message('ResendTitle');
$serverNames = $this->getServerNames();

if (count($_POST)) {
	require_once 'Flux/Recovery.php';
	require_once 'Flux/Mailer.php';

	$userid = trim($params->get('userid'));
	$email = strtolower(trim($params->get('email')));
	$groupName = $params->get('login');
	$loginAthenaGroup = Flux::getServerGroupByName($groupName);
	if (!$loginAthenaGroup) {
		$loginAthenaGroup = $session->loginAthenaGroup;
	}
	$sent = false;

	if ($loginAthenaGroup && $userid && filter_var($email, FILTER_VALIDATE_EMAIL)) {
		$createTable = Flux::config('FluxTables.AccountCreateTable');
		$sql = "SELECT login.account_id, login.userid, login.email FROM {$loginAthenaGroup->loginDatabase}.login ";
		$sql .= "JOIN {$loginAthenaGroup->loginDatabase}.{$createTable} AS created ON created.account_id = login.account_id ";
		$sql .= "WHERE LOWER(login.userid) = LOWER(?) AND LOWER(login.email) = LOWER(?) ";
		$sql .= "AND created.confirmed = 0 AND login.state = 5 AND login.sex IN ('M', 'F') LIMIT 1";
		$sth = $loginAthenaGroup->connection->getStatement($sql);
		$sth->execute(array($userid, $email));
		$account = $sth->fetch();

		if ($account) {
			$remoteAddress = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
			$recovery = new Flux_Recovery($loginAthenaGroup);
			$token = $recovery->issue($account->account_id, Flux_Recovery::PURPOSE_CONFIRM, $remoteAddress);
			if ($token) {
				$tokenHash = Flux_Recovery::hashToken($token);
				$expires = date('Y-m-d H:i:s', time() + ((int)Flux::config('EmailConfirmExpire') * 3600));
				$sql = "UPDATE {$loginAthenaGroup->loginDatabase}.{$createTable} SET ";
				$sql .= "confirm_code = ?, confirm_expire = ? WHERE account_id = ? AND confirmed = 0";
				$sth = $loginAthenaGroup->connection->getStatement($sql);
				$sth->execute(array($tokenHash, $expires, $account->account_id));

				$link = $this->url('account', 'confirm', array(
					'_host' => true,
					'token' => $token,
					'login' => $loginAthenaGroup->serverName,
				));
				$mail = new Flux_Mailer();
				$sent = $mail->send($account->email, 'Confirm your Raisupati account', 'confirm', array(
					'AccountUsername' => htmlspecialchars($account->userid),
					'ConfirmationLink' => htmlspecialchars($link),
				));
			}
		}
	}

	$session->setMessageData('If the pending account details matched, a new confirmation email was sent.');
	$this->redirect();
}
?>
