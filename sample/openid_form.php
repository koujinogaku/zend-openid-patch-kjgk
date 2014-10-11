<html>
<body>
<form method="post" action="openid_request_handler.php">
	<fieldset>
		<legend>OpenID ログイン</legend>
		<select name="openid_identifier">
		<option value="https://www.google.com/accounts/o8/id">Google</option>
		<option value="https://me.yahoo.co.jp/">Yahoo!</option>
		<option value="https://mixi.jp">mixi</option>
		<option value="https://me.yahoo.com/">Yahoo.com</option>
		<input type="submit" name="openid_action" value="login">
	</fieldset>
</form>
</body>
</html>
