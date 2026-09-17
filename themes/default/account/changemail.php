<?php if (!defined('FLUX_ROOT')) exit; ?>
<h2><?php echo htmlspecialchars(Flux::message('EmailChangeHeading')) ?></h2>

<?php if (!empty($errorMessage)): ?>
<p class="red"><?php echo htmlspecialchars($errorMessage) ?></p>
<?php endif ?>

<p><?php echo htmlspecialchars(Flux::message('EmailChangeInfo')) ?></p>

<?php if (Flux::config('RequireChangeConfirm')): ?>
<p><?php echo htmlspecialchars(Flux::message('EmailChangeInfo2')) ?></p>
<?php endif ?>

<form action="<?php echo $this->urlWithQs ?>" method="post" class="generic-form">
	<table class="generic-form-table">
		<tr>
			<th><label for="current_password">Current password</label></th>
			<td><input type="password" name="current_password" id="current_password" autocomplete="current-password" required /></td>
			<td></td>
		</tr>
		<tr>
			<th><label for="email"><?php echo htmlspecialchars(Flux::message('EmailChangeLabel')) ?></label></th>
			<td><input type="email" name="email" id="email" maxlength="39" autocomplete="email" required /></td>
			<td><p><?php echo htmlspecialchars(Flux::message('EmailChangeInputNote')) ?></p></td>
		</tr>
		<tr>
			<th><label for="confirm_email">Confirm new email</label></th>
			<td><input type="email" name="confirm_email" id="confirm_email" maxlength="39" autocomplete="email" required /></td>
			<td></td>
		</tr>
		<tr>
			<td colspan="2" align="right">
				<input type="submit" value="<?php echo htmlspecialchars(Flux::message('EmailChangeButton')) ?>" />
			</td>
			<td></td>
		</tr>
	</table>
</form>
