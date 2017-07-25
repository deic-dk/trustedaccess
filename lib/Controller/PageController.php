<?php
namespace OCA\TrustedAccess\Controller;

use OCP\IRequest;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Controller;

class PageController extends Controller {
	private $userId;

	public function __construct($AppName, IRequest $request, $UserId){
		parent::__construct($AppName, $request);
		$this->userId = $UserId;
	}
	/**
	 * @NoAdminRequired
	 * @NoCSRFRequired
	 */
	public function index() {
		return new TemplateResponse('trustedaccess', 'index',
				['somevar' => 'somevalue']);  // templates/index.php
	}
	/**
	 * @NoAdminRequired
	 * @NoCSRFRequired
	 */
	public function filetree() {
		include('trustedaccess/jqueryFileTree.php');
		exit();
	}
	
}
