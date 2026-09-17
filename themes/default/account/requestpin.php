<?php if (!defined('FLUX_ROOT')) exit; ?>
<h2>Reset PIN</h2>
<p>Enter the account name and its verified email address.</p>

<form action="<?php echo $this->urlWithQs ?>" method="post">
	<table class="vertical-table">
		<tr>
			<th><label for="pin_login"><?php echo htmlspecialchars(Flux::message('AccountServerLabel')) ?></label></th>
			<td>
				<select name="login" id="pin_login">
				<?php foreach ($serverNames as $serverName): ?>
					<option value="<?php echo htmlspecialchars($serverName) ?>"><?php echo htmlspecialchars($serverName) ?></option>
				<?php endforeach ?>
				</select>
			</td>
		</tr>
		<tr>
			<th><label for="pin_userid"><?php echo htmlspecialchars(Flux::message('AccountUsernameLabel')) ?></label></th>
			<td><input type="text" name="userid" id="pin_userid" autocomplete="username" required /></td>
		</tr>
		<tr>
			<th><label for="pin_email"><?php echo htmlspecialchars(Flux::message('AccountEmailLabel')) ?></label></th>
			<td><input type="email" name="email" id="pin_email" autocomplete="email" required /></td>
		</tr>
	</table>
	<input type="submit" value="Email PIN Reset Link" />
</form>
