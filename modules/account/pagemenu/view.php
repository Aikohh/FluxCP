<?php
// Module variables are available in page menus.
// However, access group_id checking must be done directly from the page menu.
// Minimal access checking such as $auth->actionAllowed('moduleName', 'actionName') should be performed.
$groups  = AccountLevel::getArray();

$pageMenu = array();
$canManageAccount = AccountLevel::getGroupLevel($account->group_id) <= $session->account->group_level || $auth->allowedToEditHigherPower;
if ($canManageAccount && $auth->actionAllowed('account', 'edit')) {
	$pageMenu[Flux::message('ModifyAccountLink')] = $this->url('account', 'edit', array('id' => $account->account_id));
}
if ($canManageAccount && $server->loginServer->password->usesPasswordEnrollment() && $auth->actionAllowed('account', 'enrollpass')) {
	$pageMenu['Password Recovery'] = $this->url('account', 'enrollpass', array('id' => $account->account_id));
}
if ($canManageAccount && Flux::config('PincodeEnabled') && $auth->actionAllowed('account', 'resetpin')) {
	$pageMenu['Reset PIN'] = $this->url('account', 'resetpin', array('id' => $account->account_id));
}
return $pageMenu;
?>
