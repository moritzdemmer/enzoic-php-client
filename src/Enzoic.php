<?php

namespace Enzoic;

use DateTime;

class Enzoic
{
    /**
     * @var string Version
     */
    public static $VERSION = '1.0.0';

    /**
     * @var array Settings
     */
    private $settings = array(
        'api_host' => 'api.enzoic.com',
        'api_key' => '',
        'secret' => '',
        'auth_string' => '',
        'api_url' => '',
        'request_timeout' => 5
    );

    /**
     * @var null|resource
     */
    private $ch = null; // Curl handler

    /**
     * Initializes a new Enzoic instance with API key, secret, and optionally API host.
     *
     * @param string $api_key your Enzoic API key
     * @param string $secret your Enzoic API secret
     * @param string $api_host [optional] override the default API host with an alternate host - typically not necessary
     *
     * @throws Exception Throws exception if any required dependencies are missing
     */
    public function __construct($api_key, $secret, $api_host = null)
    {
        $this->check_compatibility();

        if (!is_null($api_host)) {
            $this->settings['api_host'] = $api_host;
        }

        $this->settings['api_key'] = $api_key;
        $this->settings['secret'] = $secret;

        $this->settings['api_url'] = 'https://' . $this->settings['api_host'] . '/v1';
        $this->settings['auth_string'] = 'basic ' . base64_encode($api_key . ':' . $secret);
    }

    /**
     * Fetch the settings.
     *
     * @return array
     */
    public function getSettings()
    {
        return $this->settings;
    }

    /**
     * Set a new timeout for Enzoic network requests
     * @param integer the maximum number of seconds to wait for a request to complete
     */
    public function setRequestTimeout($requestTimeout)
    {
        $this->settings['request_timeout'] = $requestTimeout;
    }

    /**
     * Gets the current network request timeout in use
     * @return integer The number of seconds to wait for a network request to complete
     */
    public function getRequestTimeout()
    {
        return $this->settings['request_timeout'];
    }

    /**
     * Checks whether the provided password is in the Enzoic database of known, compromised passwords.  Returns extended
     * information about the compromised status of the password.
     * @see <a href="https://www.enzoic.com/docs/passwords-api">https://www.enzoic.com/docs/passwords-api</a>
     * @param $password string The password to be checked
     * @return array|null If the password is compromised, returns an array with two members, revealedInExposure and
     * relativeExposureFrequency (see docs for more explanation), is returned.  If not compromised, a null is returned.
     */
    public function checkPassword($password)
    {
        $md5 = Hashing::md5($password);
        $sha1 = Hashing::sha1($password);
        $sha256 = Hashing::sha256($password);
        $partialMD5 = substr($md5, 0, 10);
        $partialSHA1 = substr($sha1, 0, 10);
        $partialSHA256 = substr($sha256, 0, 10);

        $response = $this->make_rest_call('/passwords?partial_md5=' . $partialMD5 .
            '&partial_sha1=' . $partialSHA1 .
            '&partial_sha256=' . $partialSHA256,
            'GET', NULL);

        if ($response['status'] === 200) {
            $parsedResponse = json_decode($response['body']);
            $candidates = $parsedResponse->{'candidates'};

            for ($i = 0; $i < count($candidates); $i++) {
                if ((property_exists($candidates[$i], 'md5') && $candidates[$i]->{'md5'} === $md5) ||
                    (property_exists($candidates[$i], 'sha1') && $candidates[$i]->{'sha1'} === $sha1) ||
                    (property_exists($candidates[$i], 'sha256') && $candidates[$i]->{'sha256'} === $sha256)) {

                    $response = array();
                    $response['revealedInExposure'] = $candidates[$i]->{'revealedInExposure'};
                    $response['relativeExposureFrequency'] = $candidates[$i]->{'relativeExposureFrequency'};

                    return $response;
                }
            }
        }

        return null;
    }

    public function checkCredentials($username, $password, $lastCheckDate = NULL, $excludeHashTypes = [])
    {
        $usernameHash = Hashing::sha256($username);
        $response = $this->make_rest_call('/accounts?username=' . $usernameHash, 'GET', NULL);

        $lastCheckDateToUse = $lastCheckDate;
        if ($lastCheckDate == NULL) {
            $lastCheckDateToUse = new DateTime('1980-01-01');
        }

        if ($response['status'] === 200) {
            $parsedResponse = json_decode($response['body']);
            $lastCheckDateResponse = new DateTime($parsedResponse->{'lastBreachDate'});

            if ($lastCheckDateResponse > $lastCheckDateToUse) {
                $accountSalt = $parsedResponse->{'salt'};
                $hashesRequired = $parsedResponse->{'passwordHashesRequired'};
                $bcryptCount = 0;
                $queryString = '';
                $credentialsHashes = [];

                for ($i = 0; $i < count($hashesRequired); $i++) {
                    $hashSpec = $hashesRequired[$i];

                    if (!in_array($hashSpec->{'hashType'}, $excludeHashTypes)) {
                        if ($hashSpec->{'hashType'} != PasswordType::BCrypt || $bcryptCount <= 2) {
                            if ($hashSpec->{'hashType'} == PasswordType::BCrypt) {
                                $bcryptCount += 1;
                            }

                            $credentialsHash = $this->calcCredentialsHash($username, $password, $accountSalt, $hashSpec);

                            if ($credentialsHash != null) {
                                if ($queryString == '') {
                                    $queryString = 'partialHashes=' . substr($credentialsHash, 0, 10);
                                } else {
                                    $queryString .= '&partialHashes=' . substr($credentialsHash, 0, 10);
                                }

                                array_push($credentialsHashes, $credentialsHash);
                            }
                        }
                    }
                }

                if ($queryString != '') {
                    $response = $this->make_rest_call('/credentials?'.$queryString, 'GET', null);

                    if ($response['status'] == 200) {
                        $parsedResponse = json_decode($response['body']);

                        for ($i = 0; $i < count($parsedResponse->{'candidateHashes'}); $i++) {
                            $candidateHash = $parsedResponse->{'candidateHashes'}[$i];

                            if (in_array($candidateHash, $credentialsHashes)) {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        return false;
    }

    public function getExposuresForUser($username)
    {
        $response = $this->make_rest_call('/exposures?username=' . urlencode($username), 'GET', NULL);

        if ($response['status'] === 200) {
            return json_decode($response['body'])->{'exposures'};
        } else {
            return [];
        }
    }

    public function getExposureDetails($exposureID)
    {
        $response = $this->make_rest_call('/exposures?id=' . urlencode($exposureID), 'GET', NULL);

        if ($response['status'] === 200) {
            return json_decode($response['body']);
        }

        return null;
    }

    /**
     * Check if the current PHP setup is sufficient to run Enzoic.
     *
     * @throws Exception If any required dependencies are missing
     *
     * @return void
     */
    private function check_compatibility()
    {
        if (!extension_loaded('curl')) {
            throw new Exception('The Enzoic library requires the PHP cURL module. Please ensure it is installed');
        }

        if (!extension_loaded('json')) {
            throw new Exception('The Enzoic library requires the PHP JSON module. Please ensure it is installed');
        }

        if (!in_array('md5', hash_algos()) ||
            !in_array('sha1', hash_algos()) ||
            !in_array('sha256', hash_algos()) ||
            !in_array('sha512', hash_algos()) ||
            !in_array('whirlpool', hash_algos())) {
            throw new Exception('Enzoic requires MD5, SHA1, SHA256, SHA512, and Whirlpool support.  Make sure you have support for these, or upgrade your version of PHP.');
        }
    }

    /**
     * Makes a REST call to the Enzoic API
     * @param $restPathAndQuery
     * @param $method
     * @param $body
     * @return array
     * @throws \RuntimeException
     */
    private function make_rest_call($restPathAndQuery, $method, $body)
    {
        $apiURL = $this->settings['api_url'] . $restPathAndQuery;

        if (!is_resource($this->ch)) {
            $this->ch = curl_init();
        }

        if ($this->ch === false) {
            throw new Exception('Could not initialize cURL');
        }

        $ch = $this->ch;

        // curl handle is not reusable unless reset
        if (function_exists('curl_reset')) {
            curl_reset($ch);
        }

        // Set cURL opts and execute request
        curl_setopt($ch, CURLOPT_URL, $apiURL);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',
            'Accept: application/json',
            'Authorization: ' . $this->settings['auth_string'],
        ));

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->settings['request_timeout']);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_SAFE_UPLOAD, 1);

        if ($method === 'POST' || $method === 'PUT') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $response = array();
        $response['body'] = curl_exec($ch);
        $response['status'] = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        switch($response['status']) {
            case 0:
                throw new ConnectionException();
            case 401:
                throw new AuthenticationException();
            case 500:
                throw new UnexpectedException();
        }
        return $response;
    }

    private function calcPasswordHash($passwordType, $password, $salt)
    {
        switch ($passwordType) {
            case PasswordType::MD5:
                return Hashing::md5($password);
            case PasswordType::SHA1:
                return Hashing::sha1($password);
            case PasswordType::SHA256:
                return Hashing::sha256($password);
            case PasswordType::IPBoard_MyBB:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::myBB($password, $salt);
                }
                return null;
            case PasswordType::vBulletinPre3_8_5:
            case PasswordType::vBulletinPost3_8_5:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::vBulletin($password, $salt);
                }
                return null;
            case PasswordType::BCrypt:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::bCrypt($password, $salt);
                }
                return null;
            case PasswordType::CRC32:
                return Hashing::crc32($password);
            case PasswordType::PHPBB3:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::phpbb3($password, $salt);
                }
                return null;
            case PasswordType::CustomAlgorithm1:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::customAlgorithm1($password, $salt);
                }
                return null;
            case PasswordType::CustomAlgorithm2:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::customAlgorithm2($password, $salt);
                }
                return null;
            case PasswordType::SHA512:
                return Hashing::sha512($password);
            case PasswordType::CustomAlgorithm3:
                return Hashing::customAlgorithm3($password);
            case PasswordType::MD5Crypt:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::md5Crypt($password, $salt);
                }
                return null;
            case PasswordType::CustomAlgorithm4:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::customAlgorithm4($password, $salt);
                }
                return null;
            case PasswordType::CustomAlgorithm5:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::customAlgorithm5($password, $salt);
                }
                return null;
            case PasswordType::osCommerce_AEF:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::osCommerce_AEF($password, $salt);
                }
                return null;
            case PasswordType::DESCrypt:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::desCrypt($password, $salt);
                }
                return null;
            case PasswordType::MySQLPre4_1:
                return Hashing::mySQLPre4_1($password);
            case PasswordType::MySQLPost4_1:
                return Hashing::mySQLPost4_1($password);
            case PasswordType::PeopleSoft:
                return Hashing::peopleSoft($password);
            case PasswordType::PunBB:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::punBB($password, $salt);
                }
                return null;
            case PasswordType::CustomAlgorithm6:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::customAlgorithm6($password, $salt);
                }
                return null;
            case PasswordType::PartialMD5_20:
                return substr(Hashing::md5($password), 0, 20);
            case PasswordType::AVE_DataLife_Diferior:
                return Hashing::ave_DataLife_Diferior($password);
            case PasswordType::DjangoMD5:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::djangoMD5($password, $salt);
                }
                return null;
            case PasswordType::DjangoSHA1:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::djangoSHA1($password, $salt);
                }
                return null;
            case PasswordType::PartialMD5_29:
                return substr(Hashing::md5($password), 0, 29);
            case PasswordType::PliggCMS:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::pliggCMS($password, $salt);
                }
                return null;
            case PasswordType::RunCMS_SMF1_1:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::runCMS_SMF1_1($password, $salt);
                }
                return null;
            case PasswordType::NTLM:
                return Hashing::ntlm($password);
            case PasswordType::SHA1Dash:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::sha1Dash($password, $salt);
                }
                return null;
            case PasswordType::SHA384:
                return Hashing::sha384($password);
            case PasswordType::CustomAlgorithm7:
                if ($salt != null && strlen($salt) > 0) {
                    return Hashing::customAlgorithm7($password, $salt);
                }
                return null;
            default:
                return null;
        }
    }

    private function calcCredentialsHash($username, $password, $accountSalt, $hashSpec) {
        $salt = NULL;

        if (property_exists($hashSpec, 'salt')) {
            $salt = $hashSpec->{'salt'};
        }

        $hash = $this->calcPasswordHash($hashSpec->{'hashType'}, $password, $salt);

        if ($hash == null) return null;

        $credentialsHash = Hashing::argon2($username.'$'.$hash, $accountSalt);
        $credentialsHash = substr($credentialsHash, Hashing::lastIndexOf($credentialsHash, '$'));

        return bin2hex(base64_decode($credentialsHash));
    }
}