<?php
if (!defined('FLUX_ROOT')) exit;

$this->loginRequired();

$title = Flux::message('EmailChangeTitle');
$emailChangeTable = Flux::config('FluxTables.ChangeEmailTable');

if (count($_POST)) {
	$email = strtolower(trim($params->get('email')));
	$confirm = strtolower(trim($params->get('confirm_email')));
	$password = (string)$params->get('current_password');

	if (!$server->loginServer->isAuth($session->account->userid, $password)) {
		$errorMessage = Flux::message('InvalidLoginCredentials');
	}
	elseif (strlen($email) > 39 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
		$errorMessage = Flux::message('EmailInvalid');
	}
	elseif ($email !== $confirm) {
		$errorMessage = Flux::message('InvalidEmailconf');
	}
	elseif (strtolower($session->account->email) === $email) {
		$errorMessage = Flux::message('EmailCannotBeSame');
	}
	elseif (!Flux::config('AllowDuplicateEmails')) {
		$sql = "SELECT account_id FROM {$server->loginDatabase}.login WHERE LOWER(email) = LOWER(?) LIMIT 1";
		$sth = $server->connection->getStatement($sql);
		$sth->execute(array($email));
		if ($sth->fetch()) {
			$errorMessage = Flux::message('EmailAlreadyRegistered');
		}
	}

	if (empty($errorMessage)) {
		$remoteAddress = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
		$windowStart = date('Y-m-d H:i:s', time() - 3600);
		$sql = "SELECT COUNT(*) AS attempts FROM {$server->loginDatabase}.{$emailChangeTable} ";
		$sql .= "WHERE request_date >= ? AND (account_id = ? OR request_ip = ?)";
		$sth = $server->connection->getStatement($sql);
		$sth->execute(array($windowStart, $session->account->account_id, $remoteAddress));
		$attempts = $sth->fetch();
		if ($attempts && (int)$attempts->attempts >= 3) {
			$errorMessage = 'Too many email changes were requested. Try again in one hour.';
		}
		else {
			$token = bin2hex(random_bytes(32));
			$tokenHash = hash('sha256', $token);
			$sql = "UPDATE {$server->loginDatabase}.{$emailChangeTable} SET change_done = 1 ";
			$sql .= "WHERE account_id = ? AND change_done = 0";
			$sth = $server->connection->getStatement($sql);
			$sth->execute(array($session->account->account_id));

			$sql = "INSERT INTO {$server->loginDatabase}.{$emailChangeTable} ";
			$sql .= "(code, account_id, old_email, new_email, request_date, request_ip, change_done) ";
			$sql .= "VALUES (?, ?, ?, ?, NOW(), ?, 0)";
			$sth = $server->connection->getStatement($sql);
			$res = $sth->execute(array(
				$tokenHash,
				$session->account->account_id,
				$session->account->email,
				$email,
				$remoteAddress,
			));

			if ($res) {
				require_once 'Flux/Mailer.php';
				$link = $this->url('account', 'confirmemail', array(
					'_host' => true,
					'token' => $token,
					'login' => $session->loginAthenaGroup->serverName,
				));
				$mail = new Flux_Mailer();
				if ($mail->send($email, 'Confirm your new Raisupati email', 'changemail', array(
					'AccountUsername' => htmlspecialchars($session->account->userid),
					'OldEmail' => htmlspecialchars($session->account->email),
					'NewEmail' => htmlspecialchars($email),
					'ChangeLink' => htmlspecialchars($link),
				))) {
					$session->setMessageData(Flux::message('EmailChangeSent'));
					$this->redirect();
				}
			}
			$errorMessage = Flux::message('EmailChangeFailed');
		}
	}
}
?>
