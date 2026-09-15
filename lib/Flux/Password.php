<?php
/**
 * Password storage compatible with rAthena's passwd_type column.
 *
 * Argon2 parameters and preprocessing must stay in sync with
 * src/login/passwdcrypt.hpp in the matching rAthena source tree.
 */
class Flux_Password {
	const TYPE_LEGACY       = 0;
	const TYPE_ARGON2       = 1;
	const TYPE_ARGON2_MD5   = 2;
	const TYPE_ARGON2_WIRE  = 3;
	const FLAG_HASH_PEPPER  = 0x10;
	const FLAG_ENROLL       = 0x20;
	const TYPE_MASK         = 0x0f;

	const ARGON_MEMORY_COST = 19456;
	const ARGON_TIME_COST   = 2;
	const ARGON_THREADS     = 1;

	private $config;

	public function __construct(Flux_Config $config)
	{
		$this->config = $config;
		$wirePepper = (string)$config->get('PasswordWirePepper');
		if (strlen($wirePepper) > 20) {
			throw new RuntimeException('PasswordWirePepper exceeds rAthena client protocol limit of 20 bytes.');
		}
		if ($this->usesArgon2id() && !defined('PASSWORD_ARGON2ID')) {
			throw new RuntimeException('UseArgon2id requires PHP Argon2id support.');
		}
		if ((bool)$config->get('UsePasswordEnrollment') && !$this->usesArgon2id()) {
			throw new RuntimeException('UsePasswordEnrollment requires UseArgon2id.');
		}
	}

	public function usesArgon2id()
	{
		return (bool)$this->config->get('UseArgon2id');
	}

	public function usesPasswordEnrollment()
	{
		return $this->usesArgon2id() && (bool)$this->config->get('UsePasswordEnrollment');
	}

	/**
	 * Hash a cleartext password for a database write.
	 *
	 * @return array Array containing the encoded hash and passwd_type.
	 */
	public function hash($password)
	{
		if (!$this->usesArgon2id()) {
			return array(
				$this->config->get('UseMD5') ? md5($password) : $password,
				self::TYPE_LEGACY
			);
		}

		if (!defined('PASSWORD_ARGON2ID')) {
			throw new RuntimeException('UseArgon2id requires PHP Argon2id support.');
		}

		list($input, $type) = $this->inputForNewPassword($password);
		$pepper = (string)$this->config->get('PasswordHashPepper');
		if ($pepper !== '') {
			$input = hash_hmac('sha256', $input, $pepper);
			$type |= self::FLAG_HASH_PEPPER;
		}

		$hash = password_hash($input, PASSWORD_ARGON2ID, array(
			'memory_cost' => self::ARGON_MEMORY_COST,
			'time_cost'   => self::ARGON_TIME_COST,
			'threads'     => self::ARGON_THREADS,
		));
		if ($hash === false) {
			throw new RuntimeException('PHP failed to hash the password with Argon2id.');
		}

		return array($hash, $type);
	}

	/**
	 * Verify cleartext against legacy and all rAthena Argon2id forms.
	 */
	public function verify($password, $stored, $type)
	{
		$type = (int)$type;
		if (($type & self::FLAG_ENROLL) !== 0) {
			// Enrollment is intentionally accepted only by rAthena's game login.
			return false;
		}

		$base = $type & self::TYPE_MASK;
		if ($base === self::TYPE_LEGACY && strncmp($stored, '$argon2id$', 10) !== 0) {
			if (preg_match('/^[a-fA-F0-9]{32}$/D', $stored)) {
				return hash_equals(strtolower($stored), md5($password));
			}
			return hash_equals((string)$stored, (string)$password);
		}

		if (strncmp($stored, '$argon2id$', 10) !== 0) {
			return false;
		}

		if ($base === self::TYPE_ARGON2_MD5) {
			$input = md5($password);
		}
		elseif ($base === self::TYPE_ARGON2_WIRE) {
			$wirePepper = (string)$this->config->get('PasswordWirePepper');
			if ($wirePepper === '') {
				return false;
			}
			$input = md5($wirePepper.$password);
		}
		elseif ($base === self::TYPE_ARGON2 || $base === self::TYPE_LEGACY) {
			$input = $password;
		}
		else {
			return false;
		}

		if (($type & self::FLAG_HASH_PEPPER) !== 0) {
			$pepper = (string)$this->config->get('PasswordHashPepper');
			if ($pepper === '') {
				return false;
			}
			$input = hash_hmac('sha256', $input, $pepper);
		}

		return password_verify($input, $stored);
	}

	/**
	 * True when a verified password should be rewritten using current settings.
	 */
	public function needsRehash($stored, $type)
	{
		if (!$this->usesArgon2id()) {
			return false;
		}

		list($_input, $expectedType) = $this->inputForNewPassword('');
		if ((string)$this->config->get('PasswordHashPepper') !== '') {
			$expectedType |= self::FLAG_HASH_PEPPER;
		}
		if (((int)$type & ~self::FLAG_ENROLL) !== $expectedType) {
			return true;
		}

		return password_needs_rehash($stored, PASSWORD_ARGON2ID, array(
			'memory_cost' => self::ARGON_MEMORY_COST,
			'time_cost'   => self::ARGON_TIME_COST,
			'threads'     => self::ARGON_THREADS,
		));
	}

	public function enrollmentType($type)
	{
		return (int)$type | self::FLAG_ENROLL;
	}

	public function auditValue()
	{
		return '[redacted]';
	}

	private function inputForNewPassword($password)
	{
		$wirePepper = (string)$this->config->get('PasswordWirePepper');
		if ($wirePepper !== '') {
			return array(md5($wirePepper.$password), self::TYPE_ARGON2_WIRE);
		}
		return array($password, self::TYPE_ARGON2);
	}
}
?>
