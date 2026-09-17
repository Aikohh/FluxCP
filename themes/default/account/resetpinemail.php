<?php if (!defined('FLUX_ROOT')) exit; ?>
<h2>Confirm PIN Reset</h2>
<p>Reset the PIN for account <strong><?php echo htmlspecialchars($account->userid) ?></strong>?</p>
<p>The player must be fully logged out. The next game login will require creation of a new four-digit PIN.</p>

<form action="<?php echo $this->urlWithQs ?>" method="post">
	<input type="hidden" name="reset" value="1" />
	<input type="submit" value="Reset PIN"
		onclick="return confirm('Clear this account PIN now?')" />
</form>
