<?php
if (!defined('FLUX_ROOT')) exit;

$title = Flux::message('ResetPassTitle');
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

	if ($loginAthenaGroup && $userid && filter_var($email, FILTER_VALIDATE_EMAIL)) {
		$sql = "SELECT account_id, userid, email, group_id FROM {$loginAthenaGroup->loginDatabase}.login ";
		$sql .= "WHERE LOWER(userid) = LOWER(?) AND LOWER(email) = LOWER(?) ";
		$sql .= "AND state = 0 AND sex IN ('M', 'F') LIMIT 1";
		$sth = $loginAthenaGroup->connection->getStatement($sql);
		$sth->execute(array($userid, $email));
		$account = $sth->fetch();

		if ($account && AccountLevel::getGroupLevel($account->group_id) < Flux::config('NoResetPassGroupLevel')) {
			$remoteAddress = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
			$recovery = new Flux_Recovery($loginAthenaGroup);
			$token = $recovery->issue($account->account_id, Flux_Recovery::PURPOSE_PASSWORD, $remoteAddress);
			if ($token) {
				$link = $this->url('account', 'resetpw', array(
					'_host' => true,
					'token' => $token,
					'login' => $loginAthenaGroup->serverName,
				));
				$mail = new Flux_Mailer();
				$mail->send($account->email, 'Reset your Raisupati password', 'resetpass', array(
					'AccountUsername' => htmlspecialchars($account->userid),
					'ResetLink' => htmlspecialchars($link),
				));
			}
		}
	}

	$session->setMessageData('If the account details matched, a password reset email was sent.');
	$this->redirect();
}
?>
