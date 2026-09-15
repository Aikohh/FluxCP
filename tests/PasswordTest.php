<?php
set_include_path(__DIR__.'/../lib'.PATH_SEPARATOR.get_include_path());
require_once __DIR__.'/../lib/Flux/Config.php';
require_once __DIR__.'/../lib/Flux/Password.php';

function password_config(array $overrides = array()) {
	$config = array_merge(array(
		'UseMD5' => false,
		'UseArgon2id' => true,
		'PasswordHashPepper' => '',
		'PasswordWirePepper' => '',
		'UsePasswordEnrollment' => true,
	), $overrides);
	return new Flux_Config($config);
}

function check($condition, $message) {
	if (!$condition) {
		fwrite(STDERR, "FAIL: $message\n");
		exit(1);
	}
}

$password = 'CorrectHorse42!';

$plainCodec = new Flux_Password(password_config());
list($plainHash, $plainType) = $plainCodec->hash($password);
check($plainType === Flux_Password::TYPE_ARGON2, 'plain Argon2 type');
check($plainCodec->verify($password, $plainHash, $plainType), 'plain Argon2 verification');
check(!$plainCodec->verify('wrong', $plainHash, $plainType), 'plain Argon2 rejection');
check(!$plainCodec->verify($password, $plainHash, $plainType | Flux_Password::FLAG_ENROLL), 'FluxCP refuses enrollment login');

$pepper = 'server-side-secret';
$pepperedCodec = new Flux_Password(password_config(array('PasswordHashPepper' => $pepper)));
list($pepperedHash, $pepperedType) = $pepperedCodec->hash($password);
check($pepperedType === (Flux_Password::TYPE_ARGON2 | Flux_Password::FLAG_HASH_PEPPER), 'hash pepper type');
check(password_verify(hash_hmac('sha256', $password, $pepper), $pepperedHash), 'rAthena-compatible HMAC input');
check($pepperedCodec->verify($password, $pepperedHash, $pepperedType), 'hash pepper verification');
check($pepperedCodec->verify($password, $plainHash, $plainType), 'unpeppered rows remain verifiable');
check($pepperedCodec->needsRehash($plainHash, $plainType), 'unpeppered row migrates after verification');

$wire = 'wire-key';
$wireCodec = new Flux_Password(password_config(array(
	'PasswordHashPepper' => $pepper,
	'PasswordWirePepper' => $wire,
)));
list($wireHash, $wireType) = $wireCodec->hash($password);
check($wireType === (Flux_Password::TYPE_ARGON2_WIRE | Flux_Password::FLAG_HASH_PEPPER), 'wire and hash pepper type');
$wireInput = hash_hmac('sha256', md5($wire.$password), $pepper);
check(password_verify($wireInput, $wireHash), 'rAthena-compatible wire and HMAC input');
check($wireCodec->verify($password, $wireHash, $wireType), 'wire password verification');
check(!(new Flux_Password(password_config()))->verify($password, $wireHash, $wireType), 'wire row requires matching key');

$md5Hash = md5($password);
check($plainCodec->verify($password, $md5Hash, Flux_Password::TYPE_LEGACY), 'legacy MD5 verification');
check($plainCodec->verify($password, $password, Flux_Password::TYPE_LEGACY), 'legacy plaintext verification');

$md5Input = md5($password);
$argonMd5 = password_hash($md5Input, PASSWORD_ARGON2ID, array(
	'memory_cost' => Flux_Password::ARGON_MEMORY_COST,
	'time_cost' => Flux_Password::ARGON_TIME_COST,
	'threads' => Flux_Password::ARGON_THREADS,
));
check($plainCodec->verify($password, $argonMd5, Flux_Password::TYPE_ARGON2_MD5), 'bulk-migrated MD5 verification');

$thrown = false;
try {
	new Flux_Password(password_config(array('PasswordWirePepper' => str_repeat('x', 21))));
}
catch (RuntimeException $e) {
	$thrown = true;
}
check($thrown, 'wire key protocol length enforced');

fwrite(STDOUT, "FluxCP password compatibility tests passed\n");
?>
