<?php
if (!defined('FLUX_ROOT')) exit;

$title = Flux::message('ResetPassButton');

$account = $params->get('account');
$code    = $params->get('code');
$login   = $params->get('login');

$resetPassTable = Flux::config('FluxTables.ResetPasswordTable');

if (!$login || !$account || !$code || strlen($code) !== 32) {
	$this->deny();
}

$loginAthenaGroup = Flux::getServerGroupByName($login);
if (!$loginAthenaGroup) {
	$this->deny();
}

$sql = "SELECT userid, email FROM {$loginAthenaGroup->loginDatabase}.login WHERE account_id = ? LIMIT 1";
$sth = $loginAthenaGroup->connection->getStatement($sql);
$sth->execute(array($account));
$acc = $sth->fetch();

if (!$acc) {
	$this->deny();
}

$sql  = "SELECT id FROM {$loginAthenaGroup->loginDatabase}.$resetPassTable WHERE ";
$sql .= "account_id = ? AND code = ? AND reset_done = 0 LIMIT 1";
$sth  = $loginAthenaGroup->connection->getStatement($sql);

if (!$sth->execute(array($account, $code)) || !($reset=$sth->fetch())) {
	$this->deny();
}

$passwordCodec = $loginAthenaGroup->loginServer->password;
$auditValue = $passwordCodec->auditValue();

if ($passwordCodec->usesPasswordEnrollment()) {
	// The e-mail link proves ownership. rAthena will atomically replace the old
	// hash with whatever password the owner enters at the next game login.
	$sql = "UPDATE {$loginAthenaGroup->loginDatabase}.login SET passwd_type = passwd_type | ? WHERE account_id = ?";
	$sth = $loginAthenaGroup->connection->getStatement($sql);
	if (!$sth->execute(array(Flux_Password::FLAG_ENROLL, $account))) {
		$session->setMessageData(Flux::message('ResetPwFailed'));
		$this->redirect();
	}

	$sql  = "UPDATE {$loginAthenaGroup->loginDatabase}.$resetPassTable SET ";
	$sql .= "reset_done = 1, reset_date = NOW(), reset_ip = ?, new_password = ? WHERE id = ?";
	$sth  = $loginAthenaGroup->connection->getStatement($sql);
	if (!$sth->execute(array($_SERVER['REMOTE_ADDR'], $auditValue, $reset->id))) {
		$session->setMessageData(Flux::message('ResetPwFailed'));
		$this->redirect();
	}

	require_once 'Flux/Mailer.php';
	$mail = new Flux_Mailer();
	$sent = $mail->send($acc->email, 'Password Recovery Activated', 'passwordenroll', array('AccountUsername' => $acc->userid));
	$message = $sent ? Flux::message('ResetPwEnrollDone') : Flux::message('ResetPwEnrollDone2');
}
else {
	$newPassword = '';
	$characters  = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
	$passLength  = intval(($len=Flux::config('RandomPasswordLength')) < 8 ? 8 : $len);
	$maxIndex    = strlen($characters) - 1;
	for ($i = 0; $i < $passLength; ++$i) {
		$newPassword .= $characters[random_int(0, $maxIndex)];
	}

	$unhashedNewPassword = $newPassword;
	list($newPasswordHash, $newPasswordType) = $passwordCodec->hash($newPassword);

	if ($passwordCodec->usesArgon2id()) {
		$sql = "UPDATE {$loginAthenaGroup->loginDatabase}.login SET user_pass = ?, passwd_type = ? WHERE account_id = ?";
		$bind = array($newPasswordHash, $newPasswordType, $account);
	}
	else {
		$sql = "UPDATE {$loginAthenaGroup->loginDatabase}.login SET user_pass = ? WHERE account_id = ?";
		$bind = array($newPasswordHash, $account);
	}
	$sth = $loginAthenaGroup->connection->getStatement($sql);
	if (!$sth->execute($bind)) {
		$session->setMessageData(Flux::message('ResetPwFailed'));
		$this->redirect();
	}

	$sql  = "UPDATE {$loginAthenaGroup->loginDatabase}.$resetPassTable SET ";
	$sql .= "reset_done = 1, reset_date = NOW(), reset_ip = ?, new_password = ? WHERE id = ?";
	$sth  = $loginAthenaGroup->connection->getStatement($sql);
	if (!$sth->execute(array($_SERVER['REMOTE_ADDR'], $auditValue, $reset->id))) {
		$session->setMessageData(Flux::message('ResetPwFailed'));
		$this->redirect();
	}

	require_once 'Flux/Mailer.php';
	$mail = new Flux_Mailer();
	$sent = $mail->send($acc->email, 'Password Has Been Reset', 'newpass', array('AccountUsername' => $acc->userid, 'NewPassword' => $unhashedNewPassword));
	$message = $sent ? Flux::message('ResetPwDone') : Flux::message('ResetPwDone2');
}

$session->setMessageData($message);
$this->redirect();
?>
