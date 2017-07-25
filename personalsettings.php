<?php

require_once('apps/trustedaccess/lib/lib_chooser.php');

OCP\JSON::checkAppEnabled('trustedaccess');
OCP\User::checkLoggedIn();

OCP\Util::addscript('trustedaccess', 'personalsettings');

$tmpl = new OCP\Template( 'trustedaccess', 'personalsettings');

$tmpl->assign('is_enabled', OC_Chooser::getEnabled());
$tmpl->assign('ssl_cert_dn', OC_Chooser::getCertSubject(\OC_User::getUser()));

return $tmpl->fetchPage();
