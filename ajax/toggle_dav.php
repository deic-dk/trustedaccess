<?php

OCP\JSON::checkAppEnabled('trustedaccess');
OCP\JSON::checkLoggedIn();

require_once('apps/trustedaccess/lib/lib_chooser.php');

$old_value = OC_Chooser::getEnabled();

$new_value = $old_value == 'no' ? 'yes' : 'no';

OC_Chooser::setEnabled($new_value);

if(OC_Chooser::setEnabled($new_value)){
	$ret['message'] .= "Set enabled ".$new_value;
}
else{
	$ret['error'] = "Failed setting enabled to ".$new_value;
}

OCP\JSON::encodedPrint($ret);