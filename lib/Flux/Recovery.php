<?php
class Flux_Recovery {
	const PURPOSE_CONFIRM = 'confirmation';
	const PURPOSE_PASSWORD = 'password';
	const PURPOSE_PIN = 'pin';

	protected $server;
	protected $table;

	public function __construct($server)
	{
		$this->server = $server;
		$this->table = Flux::config('FluxTables.ResetPasswordTable');
	}

	public static function hashToken($token)
	{
		return hash('sha256', $token);
	}

	public function issue($accountID, $purpose, $requestIP, $limit = 3)
	{
		$windowStart = date('Y-m-d H:i:s', time() - 3600);
		$sql = "SELECT COUNT(*) AS attempts FROM {$this->server->loginDatabase}.{$this->table} ";
		$sql .= "WHERE purpose = ? AND request_date >= ? AND (account_id = ? OR request_ip = ?)";
		$sth = $this->server->connection->getStatement($sql);
		$sth->execute(array($purpose, $windowStart, $accountID, $requestIP));
		$row = $sth->fetch();
		if ($row && (int)$row->attempts >= $limit) {
			return false;
		}

		$sql = "UPDATE {$this->server->loginDatabase}.{$this->table} SET reset_done = 1 ";
		$sql .= "WHERE account_id = ? AND purpose = ? AND reset_done = 0";
		$sth = $this->server->connection->getStatement($sql);
		$sth->execute(array($accountID, $purpose));

		$token = bin2hex(random_bytes(32));
		$sql = "INSERT INTO {$this->server->loginDatabase}.{$this->table} ";
		$sql .= "(code, account_id, purpose, old_password, request_date, request_ip, reset_done) ";
		$sql .= "VALUES (?, ?, ?, ?, NOW(), ?, 0)";
		$sth = $this->server->connection->getStatement($sql);
		$auditValue = $this->server->loginServer->password->auditValue();
		if (!$sth->execute(array(self::hashToken($token), $accountID, $purpose, $auditValue, $requestIP))) {
			return false;
		}
		return $token;
	}

	public function find($token, $purpose)
	{
		if (!is_string($token) || !preg_match('/^[a-f0-9]{64}$/D', $token)) {
			return false;
		}
		if ($purpose === self::PURPOSE_CONFIRM) {
			$expirySeconds = max(1, (int)Flux::config('EmailConfirmExpire')) * 3600;
		}
		else {
			$expirySeconds = max(1, (int)Flux::config('RecoveryTokenExpire')) * 60;
		}
		$windowStart = date('Y-m-d H:i:s', time() - $expirySeconds);
		$sql = "SELECT recovery.id, recovery.account_id, login.userid, login.email, login.group_id ";
		$sql .= "FROM {$this->server->loginDatabase}.{$this->table} AS recovery ";
		$sql .= "JOIN {$this->server->loginDatabase}.login AS login ON login.account_id = recovery.account_id ";
		$sql .= "WHERE recovery.code = ? AND recovery.purpose = ? AND recovery.reset_done = 0 ";
		$sql .= "AND recovery.request_date >= ? AND login.sex IN ('M', 'F') LIMIT 1";
		$sth = $this->server->connection->getStatement($sql);
		$sth->execute(array(self::hashToken($token), $purpose, $windowStart));
		return $sth->fetch();
	}

	public function consume($id, $requestIP)
	{
		$sql = "UPDATE {$this->server->loginDatabase}.{$this->table} SET ";
		$sql .= "reset_done = 1, reset_date = NOW(), reset_ip = ?, new_password = ? ";
		$sql .= "WHERE id = ? AND reset_done = 0";
		$sth = $this->server->connection->getStatement($sql);
		$auditValue = $this->server->loginServer->password->auditValue();
		return $sth->execute(array($requestIP, $auditValue, $id)) && $sth->rowCount() === 1;
	}
}
?>
