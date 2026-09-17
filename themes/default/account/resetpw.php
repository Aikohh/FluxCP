<?php if (!defined('FLUX_ROOT')) exit; ?>
<h2>Choose New Password</h2>

<?php if (!empty($errorMessage)): ?>
<p class="red"><?php echo htmlspecialchars($errorMessage) ?></p>
<?php endif ?>

<p>Choose a new password for account <strong><?php echo htmlspecialchars($account->userid) ?></strong>.</p>
<p>The link will stop working after this password is changed.</p>

<form action="<?php echo $this->urlWithQs ?>" method="post">
	<table class="vertical-table">
		<tr>
			<th><label for="reset_password">New password</label></th>
			<td><input type="password" name="password" id="reset_password" autocomplete="new-password" required /></td>
		</tr>
		<tr>
			<th><label for="reset_confirm_password">Confirm password</label></th>
			<td><input type="password" name="confirm_password" id="reset_confirm_password" autocomplete="new-password" required /></td>
		</tr>
	</table>
	<input type="submit" value="Change Password" />
</form>
