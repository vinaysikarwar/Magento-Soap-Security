<?php
class WTC_SoapSecurity_Model_Api_User extends Mage_Api_Model_User
{

	    /**
     * Authenticate user name and api key and save loaded record
     *
     * @param string $username
     * @param string $apiKey
     * @return boolean
     */
    public function authenticate($username, $apiKey)
    {
        $this->loadByUsername($username);
        if (!$this->getId()) {
            return false;
        }
	
		// ip address validation for soap api code start
		$config = Mage::getStoreConfig('ssc/general/enable');
		if(!empty($config)){
			$myIp = Mage::getStoreConfig('ssc/general/ip');
			$userIp = getenv('HTTP_CLIENT_IP')?:getenv('HTTP_X_FORWARDED_FOR')?:getenv('HTTP_X_FORWARDED')?:
				getenv('HTTP_FORWARDED_FOR')?:getenv('HTTP_FORWARDED')?:getenv('REMOTE_ADDR');
			if($myIp != $userIp){
				return false;}
		}
		// ip address validation for soap api code end
			
		$auth = Mage::helper('core')->validateHash($apiKey, $this->getApiKey());
		if ($auth) {
			return true;
		} else {
			$this->unsetData();
			return false;
		}
	}
}
		
