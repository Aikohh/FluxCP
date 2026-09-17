<?php
use PHPMailer\PHPMailer\Exception as PHPMailerException;
use PHPMailer\PHPMailer\PHPMailer;

require_once FLUX_LIB_DIR . '/phpmailer7/src/Exception.php';
require_once FLUX_LIB_DIR . '/phpmailer7/src/PHPMailer.php';
require_once FLUX_LIB_DIR . '/phpmailer7/src/SMTP.php';
require_once 'Flux/LogFile.php';

class Flux_Mailer {
	protected $pm;
	protected static $errLog;
	protected static $log;

	public function __construct()
	{
		if (!self::$errLog) {
			self::$errLog = new Flux_LogFile(FLUX_DATA_DIR.'/logs/errors/mail/'.date('Ymd').'.log');
		}
		if (!self::$log) {
			self::$log = new Flux_LogFile(FLUX_DATA_DIR.'/logs/mail/'.date('Ymd').'.log');
		}

		$this->pm = $pm = new PHPMailer(true);
		$this->errLog = self::$errLog;
		$this->log = self::$log;

		if (Flux::config('MailerUseSMTP')) {
			$pm->isSMTP();
			$hosts = Flux::config('MailerSMTPHosts');
			if (is_array($hosts)) {
				$hosts = implode(';', $hosts);
			}
			$pm->Host = $hosts;
			$pm->Port = (int)(Flux::config('MailerSMTPPort') ?: 25);
			$pm->Timeout = (int)(Flux::config('MailerSMTPTimeout') ?: 10);

			if ($user = Flux::config('MailerSMTPUsername')) {
				$pm->SMTPAuth = true;
				$pm->Username = $user;
				$pm->Password = (string)Flux::config('MailerSMTPPassword');
			}
			if (Flux::config('MailerSMTPUseTLS')) {
				$pm->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
			}
			elseif (Flux::config('MailerSMTPUseSSL')) {
				$pm->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
			}
		}

		$pm->setFrom(Flux::config('MailerFromAddress'), Flux::config('MailerFromName'));
	}

	public function send($recipient, $subject, $template, array $templateVars = array())
	{
		if (!filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
			$this->errLog->puts('Rejected invalid recipient address.');
			return false;
		}

		if (array_key_exists('_ignoreTemplate', $templateVars) && $templateVars['_ignoreTemplate']) {
			$content = $template;
		}
		else {
			$templatePath = FLUX_DATA_DIR."/templates/$template.php";
			if (!file_exists($templatePath)) {
				return false;
			}

			$find = array();
			$replace = array();
			foreach ($templateVars as $key => $value) {
				$find[] = '{'.$key.'}';
				$replace[] = $value;
			}

			ob_start();
			include $templatePath;
			$content = ob_get_clean();
			if ($find) {
				$content = str_replace($find, $replace, $content);
			}
		}

		try {
			$this->pm->isHTML(true);
			$this->pm->CharSet = PHPMailer::CHARSET_UTF8;
			$this->pm->addAddress($recipient);
			$this->pm->Subject = $subject;
			$this->pm->msgHTML($content);
			$this->pm->send();
			$this->log->puts("sent email -- Subject: $subject");
			return true;
		}
		catch (PHPMailerException $e) {
			$this->errLog->puts('Mail delivery failed: '.$this->pm->ErrorInfo);
			return false;
		}
		finally {
			$this->pm->clearAddresses();
			$this->pm->clearAttachments();
		}
	}
}
?>
