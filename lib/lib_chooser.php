<?php

class OC_Chooser {

    const TRUSTED_NET = '10.2.';
    const ADMIN_NET = '10.0.0.';
    const COMPUTE_IP = '10.2.0.1';
    const IPS_TTL_SECONDS = 30;
    const IPS_CACHE_KEY = 'compute_ips';

    public static $MAX_CERTS = 10;

    public static function checkIP(){
        //\OCP\Util::writeLog('trustedaccess', 'Client IP '.isset($_SERVER['REMOTE_ADDR'])?$_SERVER['REMOTE_ADDR']:'', \OCP\Util::DEBUG);
        if(isset($_SERVER['REMOTE_ADDR']) && strpos($_SERVER['REMOTE_ADDR'], OC_Chooser::TRUSTED_NET) === 0){
        	$user_id = '';
        	if(($list_array = apc_fetch(OC_Chooser::IPS_CACHE_KEY)) === false){
        		$list_line = file_get_contents("https://".OC_Chooser::COMPUTE_IP."/steamengine/networks?f=1&action=tablelist");
        		$list_array = explode("\n", $list_line);
        		apc_add(OC_Chooser::IPS_CACHE_KEY, $list_array, OC_Chooser::IPS_TTL_SECONDS);
        		\OCP\Util::writeLog('trustedaccess', 'Refreshed IP cache: '.$list_array[3], \OCP\Util::INFO);
        	}
        	foreach($list_array as $line){
        		$entries = explode("|", $line);
        		if(count($entries)<8){
        			continue;
        		}
        		$ip = trim($entries[5]);
        		$owner = trim($entries[7]);
        		if($ip != '' && $_SERVER['REMOTE_ADDR'] == $ip && $owner != ''){
        			\OCP\Util::writeLog('trustedaccess', 'CHECK IP: '.$ip.":".$owner, \OCP\Util::INFO);
        			$user_id = $owner;
        			\OC::$session->set('user_id', $owner);
        			break;
        		}
        	}
        	\OCP\Util::writeLog('trustedaccess', 'user_id: '.$user_id, \OCP\Util::DEBUG);
        	return $user_id;
        }
        elseif(isset($_SERVER['REMOTE_ADDR']) && strpos($_SERVER['REMOTE_ADDR'], OC_Chooser::ADMIN_NET) === 0){
        	if(isset($_SERVER['PHP_AUTH_USER']) && \OC_User::userExists($_SERVER['PHP_AUTH_USER'])){
        		\OCP\Util::writeLog('trustedaccess', 'user_id: '.$_SERVER['PHP_AUTH_USER'], \OCP\Util::DEBUG);
        		
        		// Block write operations from backup servers (cmd-line sync client mess-up)
        		if((strtolower($_SERVER['REQUEST_METHOD'])=='mkcol' || strtolower($_SERVER['REQUEST_METHOD'])=='put' ||
        				strtolower($_SERVER['REQUEST_METHOD'])=='move' || strtolower($_SERVER['REQUEST_METHOD'])=='delete' ||
        				strtolower($_SERVER['REQUEST_METHOD'])=='proppatch') &&
        				stripos($_SERVER['HTTP_USER_AGENT'], "mirall")!==false &&
        				stripos($_SERVER['HTTP_USER_AGENT'], "freebsd")!==false){
        			\OCP\Util::writeLog('trustedaccess', 'Blocking write request from backup server for '.$_SERVER['PHP_AUTH_USER'],
        				\OCP\Util::ERROR);
							header($_SERVER['SERVER_PROTOCOL'] . ' 403 Forbidden');
							exit();
        		}
        		
        		\OC::$session->set('user_id', $_SERVER['PHP_AUTH_USER']);
        		return $_SERVER['PHP_AUTH_USER'];
        	}
        }
        return "";
    }

    public static function getEnabled() {
        return OCP\Config::getUserValue(\OC_User::getUser(), 'trustedaccess', 'allow_internal_dav', 'no');
    }

    /* $value: 'yes' og 'no'*/
    public static function setEnabled($value) {
        if($value != 'yes' && $value != 'no'){
            throw new \Exception("Must be yes or no: $value");
        }
        return OCP\Config::setUserValue(\OC_User::getUser(), 'trustedaccess', 'allow_internal_dav', $value);
    }

    public static function getCertIndex($user) {
    	$index = 0;
    	while($index<self::$MAX_CERTS){
    		$subject = OCP\Config::getUserValue($user, 'trustedaccess', 'ssl_certificate_subject_'.$index);
    		if(empty($subject)){
    			return $index;
    		}
    		++$index;
    	}
    	return -1;
    }

    public static function getCertSubject($user, $index=0){
    	return OCP\Config::getUserValue($user, 'trustedaccess', 'ssl_certificate_subject_'.$index);
    }

    public static function addCert($user, $subject) {
    	$index = self::getCertIndex($user);
    	if($index<0){
    		return false;
    	}
    	return OCP\Config::setUserValue($user, 'trustedaccess', 'ssl_certificate_subject_'.$index, $subject);
    }

    public static function removeCert($user, $subject) {
    	$sql = "delete FROM *PREFIX*preferences WHERE userid = ? AND appid = ? AND configkey LIKE ? AND configvalue = ?";
    	$args = array($user, 'trustedaccess', 'ssl_certificate_subject_%', $subject);
    	$query = \OCP\DB::prepare($sql);
    	return $query->execute($args);
    }

}
