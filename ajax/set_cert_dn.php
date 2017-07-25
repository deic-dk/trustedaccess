<?php

OCP\JSON::checkAppEnabled('trustedaccess');
OCP\JSON::checkLoggedIn();

require_once('apps/trustedaccess/lib/lib_chooser.php');

$dn = $_POST['dn'];
$user_id = OCP\USER::getUser();

\OCP\Util::writeLog('trustedaccess', "Setting DN: ".$user_id.":".$dn, \OCP\Util::WARN);

$ret['msg'] = "";

if($dn===""){
	if(OC_Chooser::removeCert($user_id, $dn)){
		$ret['message'] .= "Cleared DN";
	}
	else{
		$ret['error'] = "Failed clearing DN ".$dn." for user ".$user_id;
	}
}

if(OC_Chooser::addCert($user_id, $dn)){
	$ret['message'] .= "Saved DN";
}
else{
	$ret['error'] = "Failed setting DN ".$dn." for user ".$user_id;
}

OCP\JSON::encodedPrint($ret);
