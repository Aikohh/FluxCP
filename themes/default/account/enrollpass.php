<?php if (!defined('FLUX_ROOT')) exit; ?>
<h2>Next-Login Password Recovery</h2>

<table class="vertical-table">
	<tr>
		<th>Account</th>
		<td><?php echo htmlspecialchars($account->userid) ?> (<?php echo (int)$account->account_id ?>)</td>
	</tr>
	<tr>
		<th>Status</th>
		<td><?php echo $recoveryPending ? 'Waiting for a new password' : 'Inactive' ?></td>
	</tr>
</table>

<?php if ($recoveryPending): ?>
	<p><strong>Anyone who knows this account name can choose its password until recovery is cancelled or completed.</strong></p>
	<form action="<?php echo $this->urlWithQs ?>" method="post">
		<input type="hidden" name="cancel" value="1" />
		<input type="submit" value="Cancel Password Recovery"
			onclick="return confirm('Cancel next-login password recovery for this account?')" />
	</form>
<?php else: ?>
	<p><strong>After activation, the next game login will accept whatever password is entered as the account's new password.</strong></p>
	<p>Activate this only when the owner is ready to log in immediately. FluxCP web login is disabled while recovery is pending.</p>
	<form action="<?php echo $this->urlWithQs ?>" method="post">
		<input type="hidden" name="activate" value="1" />
		<input type="submit" value="Activate Next-Login Password Recovery"
			onclick="return confirm('Until the owner logs in, anyone who knows the account name can claim it. Activate recovery now?')" />
	</form>
<?php endif ?>
