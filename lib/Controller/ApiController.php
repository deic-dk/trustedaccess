<?php
namespace OCA\TrustedAccess\Controller;

use OCP\IRequest;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Controller;

class ApiController extends Controller {
	private $userId;

	public function __construct($AppName, IRequest $request, $UserId){
		parent::__construct($AppName, $request);
		$this->userId = $UserId;
	}
	/**
	 * @NoAdminRequired
	 * @NoCSRFRequired
	 */
	public function toggledav() {
		include('trustedaccess/ajax/toggle_dav.php');
		exit();
	}
	/**
	 * @NoAdminRequired
	 * @NoCSRFRequired
	 */
	public function setcertdn() {
		include('trustedaccess/ajax/set_cert_dn.php');
		exit();
	}
	
}
