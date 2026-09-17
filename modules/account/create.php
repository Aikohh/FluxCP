<?php
if (!defined('FLUX_ROOT')) exit;

if (Flux::config('UseCaptcha') && Flux::config('EnableReCaptcha')) {
	$recaptcha = Flux::config('ReCaptchaPublicKey');
	$theme = Flux::config('ReCaptchaTheme');
}

$title = Flux::message('AccountCreateTitle');

$serverNames = $this->getServerNames();

if (count($_POST)) {
	require_once 'Flux/RegisterError.php';
	
	try {
		$serverGroupName = $params->get('server');
		$username  = $params->get('username');
		$password  = $params->get('password');
		$confirm   = $params->get('confirm_password');
		$email     = trim($params->get('email_address'));
		$email2    = trim($params->get('email_address2'));
		$gender    = $params->get('gender');
		$birthdate = $params->get('birthdate_date');
		$code      = $params->get('security_code');
		
		if (!($server = Flux::getServerGroupByName($serverGroupName))) {
			throw new Flux_RegisterError('Invalid server', Flux_RegisterError::INVALID_SERVER);
		}
		
		// Woohoo! Register ;)
		$result = $server->loginServer->register($username, $password, $confirm, $email, $email2, $gender, $birthdate, $code);

		if ($result) {
			if (Flux::config('RequireEmailConfirm')) {
				require_once 'Flux/Recovery.php';
				require_once 'Flux/Mailer.php';

				$remoteAddress = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
				$recovery = new Flux_Recovery($server);
				$token = $recovery->issue($result, Flux_Recovery::PURPOSE_CONFIRM, $remoteAddress, 100);
				if (!$token) {
					throw new RuntimeException('Failed to create confirmation token.');
				}

				$createTable = Flux::config('FluxTables.AccountCreateTable');
				$tokenHash = Flux_Recovery::hashToken($token);
				$expires = date('Y-m-d H:i:s', time() + ((int)Flux::config('EmailConfirmExpire') * 3600));
				$sql = "UPDATE {$server->loginDatabase}.{$createTable} SET ";
				$sql .= "confirmed = 0, confirm_code = ?, confirm_expire = ? WHERE account_id = ?";
				$sth = $server->connection->getStatement($sql);
				$sth->execute(array($tokenHash, $expires, $result));

				$link = $this->url('account', 'confirm', array(
					'_host' => true,
					'token' => $token,
					'login' => $server->serverName,
				));
				$mail = new Flux_Mailer();
				$sent = $mail->send($email, 'Confirm your Raisupati account', 'confirm', array(
					'AccountUsername' => htmlspecialchars($username),
					'ConfirmationLink' => htmlspecialchars($link),
				));
				$session->setMessageData($sent ? Flux::message('AccountCreateEmailSent') : Flux::message('AccountCreateFailed'));
				$discordMessage = $sent ? 'Confirmation email sent.' : 'Confirmation email failed.';
			}
			else {
				$session->login($server->serverName, $username, $password, $code);
				$session->setMessageData(Flux::message('AccountCreated'));
				$discordMessage = 'Account Created.';
			}
			if(Flux::config('DiscordUseWebhook')) {
				if(Flux::config('DiscordSendOnRegister')) {
					sendtodiscord(Flux::config('DiscordWebhookURL'), 'New User registration: "'. $username . '" , ' . $discordMessage);
				}
			}
			$this->redirect();
		}
		else {
			exit('Uh oh, what happened?');
		}
	}
	catch (Flux_RegisterError $e) {
		switch ($e->getCode()) {
			case Flux_RegisterError::USERNAME_ALREADY_TAKEN:
				$errorMessage = Flux::message('UsernameAlreadyTaken');
				break;
			case Flux_RegisterError::USERNAME_TOO_SHORT:
				$errorMessage = Flux::message('UsernameTooShort');
				break;
			case Flux_RegisterError::USERNAME_TOO_LONG:
				$errorMessage = Flux::message('UsernameTooLong');
				break;
			case Flux_RegisterError::PASSWORD_HAS_USERNAME:
				$errorMessage = Flux::message ('PasswordHasUsername');
				break;
			case Flux_RegisterError::PASSWORD_TOO_SHORT:
				$errorMessage = sprintf(Flux::message('PasswordTooShort'), Flux::config('MinPasswordLength'), Flux::config('MaxPasswordLength'));
				break;
			case Flux_RegisterError::PASSWORD_TOO_LONG:
				$errorMessage = sprintf(Flux::message('PasswordTooLong'), Flux::config('MinPasswordLength'), Flux::config('MaxPasswordLength'));
				break;
			case Flux_RegisterError::PASSWORD_MISMATCH:
				$errorMessage = Flux::message('PasswordsDoNotMatch');
				break;
			case Flux_RegisterError::PASSWORD_NEED_UPPER:
				$errorMessage = sprintf(Flux::message ('PasswordNeedUpper'), Flux::config('PasswordMinUpper'));
				break;
			case Flux_RegisterError::PASSWORD_NEED_LOWER:
				$errorMessage = sprintf(Flux::message ('PasswordNeedLower'), Flux::config('PasswordMinLower'));
				break;
			case Flux_RegisterError::PASSWORD_NEED_NUMBER:
				$errorMessage = sprintf(Flux::message ('PasswordNeedNumber'), Flux::config('PasswordMinNumber'));
				break;
			case Flux_RegisterError::PASSWORD_NEED_SYMBOL:
				$errorMessage = sprintf(Flux::message ('PasswordNeedSymbol'), Flux::config('PasswordMinSymbol'));
				break;
			case Flux_RegisterError::EMAIL_ADDRESS_IN_USE:
				$errorMessage = Flux::message('EmailAddressInUse');
				break;
			case Flux_RegisterError::INVALID_EMAIL_ADDRESS:
				$errorMessage = Flux::message('InvalidEmailAddress');
				break;
			case Flux_RegisterError::INVALID_EMAIL_CONF:
				$errorMessage = Flux::message('InvalidEmailconf');
				break;
			case Flux_RegisterError::RATE_LIMITED:
				$errorMessage = 'Too many accounts were created from this address. Try again tomorrow.';
				break;
			case Flux_RegisterError::INVALID_GENDER:
				$errorMessage = Flux::message('InvalidGender');
				break;
			case Flux_RegisterError::INVALID_SERVER:
				$errorMessage = Flux::message('InvalidServer');
				break;
			case Flux_RegisterError::INVALID_SECURITY_CODE:
				$errorMessage = Flux::message('InvalidSecurityCode');
				break;
			case Flux_RegisterError::INVALID_USERNAME:
				$errorMessage = sprintf(Flux::message('AccountInvalidChars'), Flux::config('UsernameAllowedChars'));
				break;
			case Flux_RegisterError::INVALID_PASSWORD:
				$errorMessage = Flux::message ('InvalidPassword');
				break;
			case Flux_RegisterError::INVALID_BIRTHDATE:
				$errorMessage = Flux::message('InvalidBirthdate');
				break;
			default:
				$errorMessage = Flux::message('CriticalRegisterError');
				break;
		}
	}
}
?>
