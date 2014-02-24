<?php
/*------------------------------------------------------------------------
# TZ Guard Plugin
# ------------------------------------------------------------------------
# author    TemPlaza
# copyright Copyright (C) 2011 TemPlaza. All Rights Reserved.
# @license - http://www.gnu.org/licenses/gpl-2.0.html GNU/GPL
# Websites: http://www.TemPlaza.com
# Technical Support:  Forum - http://www.TemPlaza.com/Forum/
-------------------------------------------------------------------------*/

// Check to ensure this file is included in Joomla!
defined ( '_JEXEC' ) or die ( 'Restricted access' );

jimport ( 'joomla.plugin.plugin' );

require_once (JPATH_ROOT .  '/plugins/system/tz_guard/tz_guard/browser_detection.php');

class plgSystemTZ_Guard extends JPlugin {
	var $securitycode = null;
	var $black_ip = null;
	var $bot_enable = 1;
	function plgSystemTZ_Guard(& $subject, $config) {
		parent::__construct ( $subject, $config );
		$this->securitycode = $this->params->get ( 'securitycode', '' );
		$this->black_ip = $this->params->get ( 'black_ip', '' );
		$this->bot_enable = $this->params->get ( 'bot_enable', 1 );
	}

	function onAfterDispatch() {

//		$stores = &JFactory::getSession ();
		$config	= JFactory::getConfig();
		$yourip	= $this->getRealIpAddr();
        $app    = JFactory::getApplication();

		$lists = $this->getServer ();

		if (! $this->bot_enable) {
			if (($lists ['type'] == 'bot') || ($lists ['type'] == 'dow') || ($lists ['type'] == 'lib')) {
				die('Anti-Bot from '.$config->get('sitename' ));
			}
		}

		if ($this->black_ip) {
			$arr_ip = preg_split('/\n/', $this->black_ip);
			for ($i = 0; $i < count($arr_ip); $i++) {
				if ($this->black_ip($yourip, trim($arr_ip[$i]))) {
					die('('.$yourip.') Your IP has been banned. Please contact customer support if this is in error. '.$config->get('mailfrom' ));
				}
			}
		}

		if ($this->securitycode) {
			$user		=		JFactory::getUser();
			$securitycode	=	JRequest::getVar($this->securitycode, null, 'get', 'string');

			if ($app->isAdmin() && !$user->id && !isset($securitycode)) {
				$app->redirect(JURI::root());
			}
		}

	}

	/**
	 * Black IP function
	 * @param $yourip string
	 * @param $black_ip string
	 */
	function black_ip($yourip, $black_ip){
		$arr_blackip	=	preg_split('/\./', $black_ip);
		$arr_yourip		=	preg_split('/\./', $yourip);
		for ($i = 0; $i < count($arr_yourip) && $i < count($arr_blackip); $i++) {
			if ($arr_yourip[$i] != $arr_blackip[$i] && $arr_blackip[$i] != "*") {
				return FALSE;
			}
		}
		return TRUE;
	}

	function onlydomain($link) {
		$referer = parse_url ( $link );
		$domain = $referer ['host'];
		if (preg_match ( "/www/i", $domain )) {
			$only_domain = str_replace ( 'www.', '', $domain );
			$domain = $only_domain;
		}
		return $domain;
	}

	function getTraffic($referer) {
		if (($referer == '') || ($referer == $_SERVER ['HTTP_HOST'])) {
			return 'direct';
		}

		$organic = '/google|yahoo\.com|search\.com|live\.com|msn\.com|baidu\.com|altavista\.com|aol\.com|ask\.com|yandex\.com/i';
		if (preg_match ( $organic, $referer )) {
			return 'organic';
		}

		return 'referral';
	}

	function getServer() {

		$list ['referer'] = isset ( $_SERVER ['HTTP_REFERER'] ) ? $_SERVER ['HTTP_REFERER'] : '';
		$list ['referer'] = $list ['referer'] == '' ? '' : $this->onlydomain ( $list ['referer'] );
		$browser = new TZ_Guard_Browser_Detect ();
		$list ['type'] = $browser->browser_detection ( 'type' );
		$list ['browser_number'] = $browser->browser_detection ( 'number' );
		$list ['browser'] = $browser->browser_detection ( 'browser' );
		$list ['os'] = $browser->browser_detection ( 'os' );
		$list ['os_number'] = $browser->browser_detection ( 'os_number' );
		$list ['uri'] = $_SERVER ['REQUEST_URI'];
		return $list;
	}

	function convertip($ipaddress) {
		$arr_ip = split ( '\.', $ipaddress );
		$bin = '';
		foreach ( $arr_ip as $sip ) {
			$sbin = decbin ( intval ( $sip ) );
			$bin .= str_repeat ( '0', 8 - strlen ( $sbin ) ) . $sbin;
		}
		return bindec ( $bin );
	}

	// get IP
	function getRealIpAddr() {
		if (! empty ( $_SERVER ['HTTP_CLIENT_IP'] )) //check ip from share internet
{
			$ip = $_SERVER ['HTTP_CLIENT_IP'];
		} elseif (! empty ( $_SERVER ['HTTP_X_FORWARDED_FOR'] )) //to check ip is pass from proxy
{
			$ip = $_SERVER ['HTTP_X_FORWARDED_FOR'];
		} else {
			$ip = $_SERVER ['REMOTE_ADDR'];
		}
		return $ip;
	}
}