<?php

class OC_Chooser {

	private static $uservlannets = null;
	private static $trustednets = null;
	private static $vlanlisturl = null;
	private static $IPS_TTL_SECONDS = 30;
	private static $IPS_CACHE_KEY = 'compute_ips';

	public static $MAX_CERTS = 10;
	
	private static function loadNetValues(){
		if(self::$trustednets===null){
			$tnet = \OCP\Config::getSystemValue('trustednet', '');
			$tnet = trim($tnet);
			$tnets = explode(' ', $tnet);
			self::$trustednets = array_map('trim', $tnets);
			if(count(self::$trustednets)==1 && substr(self::$trustednets[0], 0, 8)==='TRUSTED_'){
				self::$trustednets = [];
			}
		}
		if(self::$uservlannets===null){
			$tnet = \OCP\Config::getSystemValue('uservlannet', '');
			$tnet = trim($tnet);
			$tnets = explode(' ', $tnet);
			self::$uservlannets = array_map('trim', $tnets);
			if(count(self::$uservlannets)==1 && substr(self::$uservlannets[0], 0, 8)==='TRUSTED_'){
				self::$uservlannets = [];
			}
		}
		if(self::$vlanlisturl===null){
			self::$vlanlisturl = trim(\OCP\Config::getSystemValue('vlanlisturl', ''));
		}
	}
	
	private static function checkTrusted($remoteIP){
		self::loadNetValues();
		foreach(self::$trustednets as $trustednet){
			if(!empty($remoteIP) && strpos($remoteIP, $trustednet)===0){
				return true;
			}
		}
		return false;
	}
	
	private static function checkUserVlan($remoteIP){
		self::loadNetValues();
		foreach(self::$uservlannets as $trustednet){
			if(!empty($remoteIP) && strpos($remoteIP, $trustednet)===0){
				return true;
			}
		}
		return false;
	}

	public static function checkIP(){
		//\OCP\Util::writeLog('trustedaccess', 'Client IP '.isset($_SERVER['REMOTE_ADDR'])?$_SERVER['REMOTE_ADDR']:'', \OCP\Util::DEBUG);
		if(isset($_SERVER['REMOTE_ADDR']) && self::checkUserVlan($_SERVER['REMOTE_ADDR'])){
			$user_id = '';
			if(($list_array = apc_fetch(self::$IPS_CACHE_KEY)) === false){
				$list_line = file_get_contents(self::$vlanlisturl);
				$list_array = explode("\n", $list_line);
				apc_add(self::$IPS_CACHE_KEY, $list_array, self::$IPS_TTL_SECONDS);
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
		elseif(isset($_SERVER['REMOTE_ADDR']) && self::checkTrusted($_SERVER['REMOTE_ADDR'])){
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

	/* $value: 'yes' and 'no'*/
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
		$index = self::getCertIndex($user);
		if($index===0){
			return true;
		}
		$sql = "delete FROM *PREFIX*preferences WHERE userid = ? AND appid = ? AND configkey LIKE ?";
		$args = array($user, 'trustedaccess', 'ssl_certificate_subject_%');
		if(!empty($subject)){
			$sql .=  " AND configvalue = ?";
			$args[] = $subject;
		}
		\OCP\Util::writeLog('trustedaccess', "Removing cert(s) ".$subject." for ".$user." with ".$sql, \OCP\Util::WARN);
		$query = \OCP\DB::prepare($sql);
		return $query->execute($args);
	}

}
