<?php

/**
* ownCloud
*
* Original:
* @author Frank Karlitschek
* @copyright 2012 Frank Karlitschek frank@owncloud.org
* 
* Adapted:
* @author Michiel de Jong, 2011
*
* Adapted:
* @author Frederik Orellana, 2013
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
* License as published by the Free Software Foundation; either
* version 3 of the License, or any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU AFFERO GENERAL PUBLIC LICENSE for more details.
*
* You should have received a copy of the GNU Affero General Public
* License along with this library.  If not, see <http://www.gnu.org/licenses/>.
*
*/

// curl --insecure --request PROPFIND https://10.2.0.254/remote.php/mydav/test/

\OCP\Util::writeLog('trustedaccess','Remote access', \OCP\Util::DEBUG);

require_once 'trustedaccess/lib/ip_auth.php';
require_once 'trustedaccess/lib/x509_auth.php';
require_once 'trustedaccess/lib/share_auth.php';
require_once 'trustedaccess/lib/nbf_auth.php';
require_once 'trustedaccess/lib/server.php';
require_once 'trustedaccess/lib/share_objecttree.php';

use OCA\DAV\Connector\Sabre\Auth;
use OCA\DAV\Connector\Sabre\BearerAuth;
use OCA\DAV\Connector\Sabre\DavAclPlugin;
use OCA\DAV\Connector\Sabre\DummyGetResponsePlugin;
use OCA\DAV\Connector\Sabre\FakeLockerPlugin;
use OCA\DAV\Connector\Sabre\FilesPlugin;
use OCA\DAV\Connector\Sabre\TagsPlugin;
use OCA\DAV\DAV\PublicAuth;
use OCA\DAV\DAV\CustomPropertiesBackend;
use OCA\DAV\Connector\Sabre\QuotaPlugin;
use OCA\DAV\Files\BrowserErrorPagePlugin;
use OCA\DAV\SystemTag\SystemTagPlugin;
use Sabre\DAV\Auth\Plugin;
use OCA\DAV\Comments\CommentsPlugin;
use OCA\DAV\Connector\Sabre\CopyEtagHeaderPlugin;
use OCP\SabrePluginEvent;
use SearchDAV\DAV\SearchPlugin;

OC_App::loadApps(array('filesystem','authentication'));

OCP\App::checkAppEnabled('trustedaccess');

// This may be a browser accessing a webdav URL - and the browser may already be logged in
if(OC_User::isLoggedIn()){
	$loggedInUser = \OC_User::getUser();
}

if(OCP\App::isEnabled('user_group_admin')){
	OC::$CLASSPATH['OC_User_Group_Admin_Backend'] ='apps/user_group_admin/lib/backend.php';
	OC_Group::useBackend( new OC_User_Group_Admin_Backend() );
}

ini_set('default_charset', 'UTF-8');
//ini_set('error_reporting', '');
//@ob_clean();

// only need authentication apps
//$RUNTIME_APPTYPES=array('authentication');
//OC_App::loadApps($RUNTIME_APPTYPES);

// no php execution timeout for webdav
if (strpos(@ini_get('disable_functions'), 'set_time_limit') === false) {
	@set_time_limit(0);
}
ignore_user_abort(true);
// Turn off output buffering to prevent memory problems
OC_Util::obEnd();

//OC_Util::setupFS($ownCloudUser);

// Create ownCloud Dir
//$rootDir = new OC_Connector_Sabre_Directory('');
//$objectTree = new \OC\Connector\Sabre\ObjectTree($rootDir);
$objectTree = new Share_ObjectTree();
//$objectTree = new \OC\Connector\Sabre\ObjectTree();

//$server = new Sabre_DAV_Server($rootDir);
$server = new OC_Connector_Sabre_Server_chooser($objectTree);

//$requestBackend = new OC_Connector_Sabre_Request();
//$server->httpRequest = $requestBackend;
//$server->httpRequest = \OC::$server->getRequest();

// Path
//$baseuri = OC_App::getAppWebPath('trustedaccess').'appinfo/remote.php';
$baseuri = OC::$WEBROOT."/remote.php/mydav";
// Known aliases
if(strpos($_SERVER['REQUEST_URI'], OC::$WEBROOT."/files/")===0){
	$baseuri = OC::$WEBROOT."/files";
}
if(strpos($_SERVER['REQUEST_URI'], OC::$WEBROOT."/public/")===0){
	$baseuri = OC::$WEBROOT."/public";
}
$server->setBaseUri($baseuri);

/////// new
$request = \OC::$server->getRequest();

$authBackend = new Auth(
		\OC::$server->getSession(),
		\OC::$server->getUserSession(),
		$request,
		\OC::$server->getTwoFactorAuthManager(),
		\OC::$server->getBruteForceThrottler()
);
$authPlugin = new \Sabre\DAV\Auth\Plugin($authBackend);
$bearerAuthBackend = new \OCA\DAV\Connector\Sabre\BearerAuth(
		\OC::$server->getUserSession(),
		\OC::$server->getSession(),
		$request
);
$authPlugin->addBackend($bearerAuthBackend);
// because we are throwing exceptions this plugin has to be the last one
$authPlugin->addBackend($authBackend);

//\OCP\Util::writeLog('trustedaccess','Session '.serialize(\OC::$server->getUserSession()->getUser()), \OCP\Util::WARN);

// Set URL explicitly due to reverse-proxy situations
$server->httpRequest->setUrl($request->getRequestUri());

// allow setup of additional auth backends
$dispatcher = \OC::$server->getEventDispatcher();
$event = new SabrePluginEvent($server);
$dispatcher->dispatch('OCA\DAV\Connector\Sabre::authInit', $event);

$authPlugin->addBackend(new PublicAuth());

////////

// Auth backends
//$_SERVER['REQUEST_URI'] = preg_replace("/^\/public/", "/remote.php/mydav/", $_SERVER['REQUEST_URI']);
$authBackendIP = new Sabre\DAV\Auth\Backend\IP();
$authPlugin->addBackend($authBackendIP);

$authBackendX509 = new Sabre\DAV\Auth\Backend\X509();
$authPlugin->addBackend($authBackendX509);

//$authBackend = new OC_Connector_Sabre_Auth();
$authBackendNBF = new OC_Connector_Sabre_Auth_NBF();
$authPlugin->addBackend($authBackendNBF);

$server->addPlugin($authPlugin);

//if(strpos($_SERVER['REQUEST_URI'], "/files/")!==0){
if($baseuri == OC::$WEBROOT."/public"){
	$authBackendShare = new Sabre\DAV\Auth\Backend\Share($baseuri);
	$authPlugin->addBackend($authBackendShare);
	$server->addPlugin($authPluginShare);

	if($authBackendShare->path!==null){
		//$_SERVER['REQUEST_URI'] = $baseuri."/".$authBackendShare->path;
		//$server->setBaseUri($baseuri."/".$authBackendShare->token);
		$objectTree->auth_token = $authBackendShare->token;
		$objectTree->auth_path = $authBackendShare->path;
		$objectTree->allowUpload = $authBackendShare->allowUpload;
	}
}

// Also make sure there is a 'data' directory, writable by the server. This directory is used to store information about locks
$lockPlugin = new \OCA\DAV\Connector\Sabre\LockPlugin();
$server->addPlugin($lockPlugin);

///////// new
$server->addPlugin(new \Sabre\DAV\Sync\Plugin());
// acl
$acl = new DavAclPlugin();
$acl->principalCollectionSet = [
'principals/users', 'principals/groups'
		];
$acl->defaultUsernamePath = 'principals/users';
$server->addPlugin($acl);

// system tags plugins
$server->addPlugin(new SystemTagPlugin(
		\OC::$server->getSystemTagManager(),
		\OC::$server->getGroupManager(),
		\OC::$server->getUserSession()
));

// comments plugin
$server->addPlugin(new CommentsPlugin(
		\OC::$server->getCommentsManager(),
		\OC::$server->getUserSession()
));

$server->addPlugin(new CopyEtagHeaderPlugin());

// Some WebDAV clients do require Class 2 WebDAV support (locking), since
// we do not provide locking we emulate it using a fake locking plugin.
if($request->isUserAgent([
		'/WebDAVFS/',
		'/Microsoft Office OneNote 2013/',
		'/^Microsoft-WebDAV/',// Microsoft-WebDAV-MiniRedir/6.1.7601
		])) {
	$server->addPlugin(new FakeLockerPlugin());
}

if (BrowserErrorPagePlugin::isBrowserRequest($request)) {
	$server->addPlugin(new BrowserErrorPagePlugin());
}

/////////

$server->addPlugin(new \Sabre\DAV\Browser\Plugin(false)); // Show something in the Browser, but no upload
$server->addPlugin(new \OCA\DAV\Connector\Sabre\MaintenancePlugin(\OC::$server->getConfig()));
$logger = \OC::$server->getLogger();
$server->addPlugin(new \OCA\DAV\Connector\Sabre\ExceptionLoggerPlugin('mydav', $logger));

// Accept mod_rewrite internal redirects.
$_SERVER['REQUEST_URI'] = preg_replace("|^".OC::$WEBROOT."/*remote.php/webdav|",
		OC::$WEBROOT."/remote.php/mydav/", $_SERVER['REQUEST_URI']);
// Accept include by remote.php from files_sharding.
$_SERVER['REQUEST_URI'] = preg_replace("|^".OC::$WEBROOT."/*remote.php/davs|",
		OC::$WEBROOT."/remote.php/mydav/", $_SERVER['REQUEST_URI']);
//$_SERVER['REQUEST_URI'] = preg_replace("/^\/files/", "/remote.php/mydav/", $_SERVER['REQUEST_URI']);
//\OCP\Util::writeLog('trustedaccess','REQUEST '.serialize($_SERVER), \OCP\Util::WARN);
//\OCP\Util::writeLog('trustedaccess','user '.$authPlugin->getCurrentUser(), \OCP\Util::WARN);

if(!empty($_SERVER['BASE_URI'])){
	// Accept include from remote.php from other apps and set root accordingly
	$server->setBaseUri($_SERVER['BASE_URI']);
}

// In the case of a move request, a header will contain the destination
// with hard-wired host name. Change this host name on redirect.
if(!empty($_SERVER['HTTP_DESTINATION'])){
	$_SERVER['HTTP_DESTINATION'] = preg_replace("|^".OC::$WEBROOT."/*remote.php/webdav|",
			OC::$WEBROOT."/remote.php/mydav/", $_SERVER['HTTP_DESTINATION']);
	// Accept include by remote.php from files_sharding.
	$_SERVER['HTTP_DESTINATION'] = preg_replace("|^".OC::$WEBROOT."/*remote.php/davs|",
			OC::$WEBROOT."/remote.php/mydav/", $_SERVER['HTTP_DESTINATION']);
}

// wait with registering these until auth is handled and the filesystem is setup
$server->on('beforeMethod', function () use ($server, $objectTree) {
	//////// new
	$view = \OC\Files\Filesystem::getView();
	$server->addPlugin(
			new FilesPlugin(
					$server->tree,
					\OC::$server->getConfig(),
					\OC::$server->getRequest(),
					\OC::$server->getPreviewManager(),
					false,
					!\OC::$server->getConfig()->getSystemValue('debug', false)
			)
	);
	////////
	if(!empty($_SERVER['BASE_DIR'])){
		\OCP\Util::writeLog('trustedaccess','Non-files access: '.$_SERVER['BASE_DIR'], \OCP\Util::WARN);
		\OC\Files\Filesystem::tearDown();
		\OC\Files\Filesystem::init($_SERVER['PHP_AUTH_USER'], $_SERVER['BASE_DIR']);
		$view = new \OC\Files\View($_SERVER['BASE_DIR']);
	}
	else{
		$view = \OC\Files\Filesystem::getView();
	}
	$rootInfo = $view->getFileInfo('');
	
	// Create ownCloud Dir
	$mountManager = \OC\Files\Filesystem::getMountManager();
	$rootDir = new \OCA\DAV\Connector\Sabre\Directory($view, $rootInfo);
	$objectTree->init($rootDir, $view, $mountManager);

	// This was to bump up quota if smaller than freequota WITHOUT
	// writing the bigger quota to the DB.
	// Unfortunately it only works for the initial size check.
	// When actually writing, fopen is wrapped with \OC\Files\Stream\Quota::wrap,
	// and the DB quota is checked again.
	/*if(\OCP\App::isEnabled('files_accounting')){
		require_once 'files_accounting/lib/quotaplugin.php';
		$server->addPlugin(new OC_Connector_Sabre_QuotaPlugin_files_accounting($view));
	}
	else{*/
		//$server->addPlugin(new OC_Connector_Sabre_QuotaPlugin($view));
	//}
	//////// new
	$server->addPlugin(
			new \Sabre\DAV\PropertyStorage\Plugin(
					new CustomPropertiesBackend(
							$server->tree,
							\OC::$server->getDatabaseConnection(),
							\OC::$server->getUserSession()->getUser()
					)
			)
	);
	if ($view !== null) {
		$server->addPlugin(
				new QuotaPlugin($view));
	}
	$server->addPlugin(
			new TagsPlugin(
					$server->tree, \OC::$server->getTagManager()
			)
	);
	$server->addPlugin(new SearchPlugin(new \OCA\DAV\Files\FileSearchBackend(
		$server->tree,
		OC::$server->getUserSession()->getUser(),
		\OC::$server->getRootFolder(),
		\OC::$server->getShareManager(),
		$view
	)));
	////////
	
}, 30); // priority 30: after auth (10) and acl(20), before lock(50) and handling the request

require_once('apps/trustedaccess/appinfo/apache_note_user.php');

$ok = true;
if(\OCP\App::isEnabled('files_sharding')){
	$userServerAccess = \OCA\FilesSharding\Lib::getUserServerAccess();
	// Block all access if account is locked on server
	if(\OCP\App::isEnabled('files_sharding') &&
		$userServerAccess!=\OCA\FilesSharding\Lib::$USER_ACCESS_ALL &&
		$userServerAccess!=\OCA\FilesSharding\Lib::$USER_ACCESS_READ_ONLY){
		$ok = false;
	}
}

// Block write operations on r/o server
if(\OCP\App::isEnabled('files_sharding') &&
		$userServerAccess==\OCA\FilesSharding\Lib::$USER_ACCESS_READ_ONLY &&
		(strtolower($_SERVER['REQUEST_METHOD'])=='mkcol' || strtolower($_SERVER['REQUEST_METHOD'])=='put' ||
		strtolower($_SERVER['REQUEST_METHOD'])=='move' || strtolower($_SERVER['REQUEST_METHOD'])=='delete' ||
		strtolower($_SERVER['REQUEST_METHOD'])=='proppatch')){
	$ok = false;
}

// And off we go!
if($ok){
	$server->exec();
}
else{
	//throw new \Sabre\DAV\Exception\Forbidden($_SERVER['REQUEST_METHOD'].' currently not allowed.');
	$server->httpResponse->sendStatus(403);
}

// Deal with browsers
$user_id = \OC_User::getUser();
if(!empty($loggedInUser) && $loggedInUser!=$user_id){
	\OC_Util::teardownFS();
	\OC_User::setUserId($loggedInUser);
	\OC_Util::setupFS($loggedInUser);
}
elseif(session_status()===PHP_SESSION_ACTIVE){
	session_destroy();
	$session_id = session_id();
	unset($_COOKIE[$session_id]);
}

