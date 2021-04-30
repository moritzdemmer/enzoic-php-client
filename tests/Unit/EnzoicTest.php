<?php

namespace Enzoic\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Enzoic\Enzoic;

class EnzoicTest extends TestCase
{
    protected function setUp()
    {
    }

    public function testConstructor()
    {
        $enzoic = new Enzoic(getenv('PP_API_KEY'), getenv('PP_API_SECRET'));

        $settings = $enzoic->getSettings();
        $this->assertEquals(getEnv('PP_API_KEY'), $settings['api_key']);
        $this->assertEquals(getEnv('PP_API_SECRET'), $settings['secret']);
        $this->assertEquals('api.enzoic.com', $settings['api_host']);
        $this->assertEquals('https://api.enzoic.com/v1', $settings['api_url']);

        //echo(crypt('12345', '$2a$12$2bULeXwv2H34SXkT1giCZe'));
        //echo(crypt('123456789', '$H$993WP3hbz'));
        //echo('<br/>');
        //echo(exec('echo -n "password" | argon2 "4zU7iIzt6Ej+PH[ol+ir7i\!Y*K-d90DB" -d -t 2 -k 1024 -p 2 -l 20 -e'));
    }

    public function testCheckPassword()
    {
        $enzoic = $this->getEnzoic();

        $response = $enzoic->checkPassword('kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd');
        $this->assertEquals(null, $response);

        $response = $enzoic->checkPassword('``--...____...--\'\'');
        $this->assertEquals($response, [
            'revealedInExposure' => false,
            'relativeExposureFrequency' => 0
        ]);

        $response = $enzoic->checkPassword('123456');
        $this->assertEquals($response, [
            'revealedInExposure' => true,
            'relativeExposureFrequency' => 28
        ]);
    }

    public function testCheckCredentials()
    {
        $enzoic = $this->getEnzoic();

        for ($i = 1; $i <= 36; $i++) {
            if (in_array($i, [4, 9, 11, 12, 14])) continue;

            echo "testing" . $i . "\n";

            $response = $enzoic->checkCredentials('eicar_' . $i . '@enzoic.com', '123456');

            $this->assertEquals(true, $response);
        }
    }

    public function testGetExposuresForUser()
    {
        $enzoic = $this->getEnzoic();

        $response = $enzoic->getExposuresForUser('@@bogus-username@@');
        $this->assertEquals([], $response);

        $response = $enzoic->getExposuresForUser('eicar');
        $this->assertEquals([
            "5820469ffdb8780510b329cc", "58258f5efdb8780be88c2c5d", "582a8e51fdb87806acc426ff", "583d2f9e1395c81f4cfa3479", "59ba1aa369644815dcd8683e", "59cae0ce1d75b80e0070957c", "5bc64f5f4eb6d894f09eae70", "5bdcb0944eb6d8a97cfacdff"
        ], $response);
    }

    public function testGetExposureDetails()
    {
        $enzoic = $this->getEnzoic();

        $response = $enzoic->getExposureDetails('111111111111111111111111');
        $this->assertEquals(NULL, $response);

        $response = $enzoic->getExposureDetails('5820469ffdb8780510b329cc');
        $this->assertEquals((object)[
            'id' => '5820469ffdb8780510b329cc',
            'title' => 'last.fm',
            'entries' => 81967007,
            'date' => '2012-03-01T00:00:00.000Z',
            'category' => 'Music',
            'passwordType' => 'MD5',
            'exposedData' => [
                'Emails',
                'Passwords',
                'Usernames',
                'Website Activity'
            ],
            'dateAdded' => '2016-11-07T09:17:19.000Z',
            'sourceURLs' => [],
            'domainsAffected' => 1219053
        ], $response);
    }

    private function getEnzoic()
    {
        return new Enzoic(getenv('PP_API_KEY'), getenv('PP_API_SECRET'));
    }
}