<?php
if (!defined('FLUX_ROOT')) exit;
$siteTitle = Flux::config('SiteTitle');
$emailTitle = sprintf('%s: Reset PIN', $siteTitle);
?>
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8" />
		<title><?php echo htmlspecialchars($emailTitle) ?></title>
	</head>
	<body>
		<h2><?php echo htmlspecialchars($emailTitle) ?></h2>
		<p>A PIN reset was requested for account <strong>{AccountUsername}</strong>.</p>
		<p><a href="{ResetLink}">{ResetLink}</a></p>
		<p>If you did not request this, ignore this email. The link expires automatically.</p>
	</body>
</html>
