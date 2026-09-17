<?php
if (!defined('FLUX_ROOT')) exit;

if (!Flux::config('PincodeEnabled')) {
	$this->deny();
}

$title = 'Reset PIN';
$serverNames = $this->getServerNames();

if (count($_POST)) {
	require_once 'Flux/Recovery.php';
	require_once 'Flux/Mailer.php';

	$userid = trim($params->get('userid'));
	$email = strtolower(trim($params->get('email')));
	$groupName = $params->get('login');
	$loginAthenaGroup = Flux::getServerGroupByName($groupName);

	if ($loginAthenaGroup && $userid && filter_var($email, FILTER_VALIDATE_EMAIL)) {
		$sql = "SELECT account_id, userid, email, group_id FROM {$loginAthenaGroup->loginDatabase}.login ";
		$sql .= "WHERE LOWER(userid) = LOWER(?) AND LOWER(email) = LOWER(?) ";
		$sql .= "AND state = 0 AND pincode != '' AND sex IN ('M', 'F') LIMIT 1";
		$sth = $loginAthenaGroup->connection->getStatement($sql);
		$sth->execute(array($userid, $email));
		$account = $sth->fetch();

		if ($account && AccountLevel::getGroupLevel($account->group_id) < Flux::config('NoResetPassGroupLevel')) {
			$remoteAddress = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
			$recovery = new Flux_Recovery($loginAthenaGroup);
			$token = $recovery->issue($account->account_id, Flux_Recovery::PURPOSE_PIN, $remoteAddress);
			if ($token) {
				$link = $this->url('account', 'resetpinemail', array(
					'_host' => true,
					'token' => $token,
					'login' => $loginAthenaGroup->serverName,
				));
				$mail = new Flux_Mailer();
				$mail->send($account->email, 'Reset your Raisupati PIN', 'resetpin', array(
					'AccountUsername' => htmlspecialchars($account->userid),
					'ResetLink' => htmlspecialchars($link),
				));
			}
		}
	}

	$session->setMessageData('If the account details matched, a PIN reset email was sent.');
	$this->redirect();
}
?>
