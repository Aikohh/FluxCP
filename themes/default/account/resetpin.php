<?php if (!defined('FLUX_ROOT')) exit; ?>
<h2>Reset Player PIN</h2>

<table class="vertical-table">
	<tr>
		<th>Account</th>
		<td><?php echo htmlspecialchars($account->userid) ?> (<?php echo (int)$account->account_id ?>)</td>
	</tr>
	<tr>
		<th>PIN status</th>
		<td><?php echo $pinSet ? 'PIN is set' : 'No PIN is set' ?></td>
	</tr>
</table>

<p><strong>The player must fully log out of the game before this reset.</strong></p>
<p>The next game login will require the player to create a new four-digit PIN. The existing PIN is never displayed.</p>

<?php if ($pinSet): ?>
<form action="<?php echo $this->urlWithQs ?>" method="post">
	<input type="hidden" name="reset" value="1" />
	<input type="submit" value="Reset Player PIN"
		onclick="return confirm('Reset this account PIN and require a new one at the next game login?')" />
</form>
<?php else: ?>
<p>No reset is needed. The player will be asked to create a PIN at the next game login.</p>
<?php endif ?>
