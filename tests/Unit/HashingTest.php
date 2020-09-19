<?php

namespace Enzoic\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Enzoic;

class HashingTest extends TestCase
{
    protected function setUp()
    {
    }

    public function testMD5()
    {
        $this->assertEquals('e10adc3949ba59abbe56e057f20f883e', Enzoic\Hashing::md5('123456'));
    }

    public function testSHA1()
    {
        $this->assertEquals('7c4a8d09ca3762af61e59520943dc26494f8941b', Enzoic\Hashing::sha1('123456'));
    }

    public function testSHA256()
    {
        $this->assertEquals('8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92',
            Enzoic\Hashing::sha256('123456'));
    }

    public function testSHA512()
    {
        $this->assertEquals('ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff',
            Enzoic\Hashing::sha512('test'));
    }

    public function testCustomAlgorithm3() {
        $this->assertEquals('bf26c40b9e71d9aeb76d5ad4ae5b8db2',
            Enzoic\Hashing::customAlgorithm3('123456'));
    }

    public function testWhirlpool()
    {
        $this->assertEquals('fd9d94340dbd72c11b37ebb0d2a19b4d05e00fd78e4e2ce8923b9ea3a54e900df181cfb112a8a73228d1f3551680e2ad9701a4fcfb248fa7fa77b95180628bb2',
            Enzoic\Hashing::whirlpool('123456'));
    }

    public function testMyBB()
    {
        $this->assertEquals('2e705e174e9df3e2c8aaa30297aa6d74', Enzoic\Hashing::myBB('123456', ';;!_X'));
    }

    public function testVBulletin()
    {
        $this->assertEquals('57ce303cdf1ad28944d43454cea38d7a', Enzoic\Hashing::vBulletin('123456789', ']G@'));
    }

    public function testBCrypt()
    {
        $this->assertEquals('$2a$12$2bULeXwv2H34SXkT1giCZeJW7A6Q0Yfas09wOCxoIC44fDTYq44Mm',
            Enzoic\Hashing::bCrypt('12345', '$2a$12$2bULeXwv2H34SXkT1giCZe'));
    }

    public function testPHPBB3()
    {
        $this->assertEquals('$H$993WP3hbzy0N22X06wxrCc3800D2p41',
            Enzoic\Hashing::phpbb3('123456789', '$H$993WP3hbz'));
    }

    public function testCustomAlgorithm1()
    {
        $this->assertEquals('cee66db36504915f48b2d545803a4494bb1b76b6e9d8ba8c0e6083ff9b281abdef31f6172548fdcde4000e903c5a98a1178c414f7dbf44cffc001aee8e1fe206',
            Enzoic\Hashing::customAlgorithm1('123456', '00new00'));

        $this->assertEquals('089a6867939a1bfa2ceaf119ab7b9a2d8b8c9169b399372f7ca272f9c50858ab78eb5419e8a77b546a0de02191c22b7a8b3f82b9a6064c97e2efd9c08ab50f18',
            Enzoic\Hashing::customAlgorithm1('123456', '123'));
    }

    public function testCustomAlgorithm2()
    {
        $this->assertEquals('579d9ec9d0c3d687aaa91289ac2854e4',
            Enzoic\Hashing::customAlgorithm2('123456', '123'));
    }

    public function testCustomAlgorithm4()
    {
        $this->assertEquals('$2y$12$Yjk3YjIzYWIxNDg0YWMzZOpp/eAMuWCD3UwX1oYgRlC1ci4Al970W',
            Enzoic\Hashing::customAlgorithm4('1234', '$2y$12$Yjk3YjIzYWIxNDg0YWMzZO'));
    }

    public function testCustomAlgorithm5()
    {
        $this->assertEquals('69e7ade919a318d8ecf6fd540bad9f169bce40df4cae4ac1fb6be2c48c514163',
            Enzoic\Hashing::customAlgorithm5('password', '123456'));
    }

    public function testCustomAlgorithm6()
    {
        $this->assertEquals('f0f8e902ca7a41c634c5c8247d4b94f2c9b351fb',
            Enzoic\Hashing::customAlgorithm6('123456', '123'));
    }

    public function testCrc32()
    {
        $this->assertEquals('0972d361', Enzoic\Hashing::crc32('123456'));
    }

    public function testMD5Crypt()
    {
        $this->assertEquals('$1$4d3c09ea$hPwyka2ToWFbLTOq.yFjf.',
            Enzoic\Hashing::md5Crypt('123456', '$1$4d3c09ea'));
    }

    public function testOsCommerce_AEF()
    {
        $this->assertEquals('d2bc2f8d09990ebe87c809684fd78c66',
            Enzoic\Hashing::osCommerce_AEF('password', '123'));
    }

    public function testDESCrypt()
    {
        $this->assertEquals('X.OPW8uuoq5N.',
            Enzoic\Hashing::desCrypt('password', 'X.'));
    }

    public function testMySqlPre4_1()
    {
        $this->assertEquals('5d2e19393cc5ef67', Enzoic\Hashing::mySqlPre4_1('password'));
    }

    public function testMySqlPost4_1()
    {
        $this->assertEquals('*94bdcebe19083ce2a1f959fd02f964c7af4cfc29', Enzoic\Hashing::mySqlPost4_1('test'));
    }

    public function testPeopleSoft()
    {
        $this->assertEquals('3weP/BR8RHPLP2459h003IgJxyU=', Enzoic\Hashing::peopleSoft('TESTING'));
    }

    public function testPunBB()
    {
        $this->assertEquals('0c9a0dc3dd0b067c016209fd46749c281879069e', Enzoic\Hashing::punBB('password', '123'));
    }

    public function testAve_DataLife_Diferior()
    {
        $this->assertEquals('696d29e0940a4957748fe3fc9efd22a3', Enzoic\Hashing::ave_DataLife_Diferior('password'));
    }

    public function testDjangoMD5()
    {
        $this->assertEquals('md5$c6218$346abd81f2d88b4517446316222f4276', Enzoic\Hashing::djangoMD5('password', 'c6218'));
    }

    public function testDjangoSHA1()
    {
        $this->assertEquals('sha1$c6218$161d1ac8ab38979c5a31cbaba4a67378e7e60845',
            Enzoic\Hashing::djangoSHA1('password', 'c6218'));
    }

    public function testPliggCMS()
    {
        $this->assertEquals('1230de084f38ace8e3d82597f55cc6ad5d6001568e6',
            Enzoic\Hashing::pliggCMS('password', '123'));
    }

    public function testRunCMS_SMF1_1()
    {
        $this->assertEquals('0de084f38ace8e3d82597f55cc6ad5d6001568e6',
            Enzoic\Hashing::runCMS_SMF1_1('password', '123'));
    }

    public function testNTLM()
    {
        $this->assertEquals('8846f7eaee8fb117ad06bdd830b7586c',
            Enzoic\Hashing::ntlm('password'));
    }

    public function testSHA1Dash()
    {
        $this->assertEquals('000007b62a7bad687566fbb20b4ee69e390f5b9a',
            Enzoic\Hashing::sha1Dash('ayobami88', '876401270e0012121de48a811718dfaad031b069'));
    }

    public function testCustomAlgorithm7()
    {
        $this->assertEquals('0008fc1cbf16498623cf3772dc3da688a75d19cff416bc22f88807665700f033',
            Enzoic\Hashing::customAlgorithm7('Laika5882', '9602501'));
    }

    public function testArgon2()
    {
        $this->assertEquals('$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o',
            Enzoic\Hashing::argon2('123456', 'saltysalt'));
        $this->assertEquals('$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o',
            Enzoic\Hashing::argon2('123456', '$argon2d$v=19$m=1024,t=3,p=2,l=20$c2FsdHlzYWx0'));
        $this->assertEquals('$argon2i$v=19$m=1024,t=2,p=2$c29tZXNhbHQ$bBKumUNszaveOgEhcaWl6r6Y91Y',
            Enzoic\Hashing::argon2('password', '$argon2i$v=19$m=1024,t=2,p=2,l=20$c29tZXNhbHQ'));
        $this->assertEquals('$argon2i$v=19$m=4096,t=2,p=4$c29tZXNhbHQ$M2X6yo+ZZ8ROwC7MB6/+1yMhGytTzDczBMgo3Is7ptY',
            Enzoic\Hashing::argon2('password', '$argon2i$v=19$m=4096,t=2,p=4,l=32$c29tZXNhbHQ'));
        $this->assertEquals('$argon2i$v=19$m=4096,t=2,p=4$c29tZXNhbHQ$ZPidoNOWM3jRl0AD+3mGdZsq+GvHprGL',
            Enzoic\Hashing::argon2('password', '$argon2i$v=19$m=4096,t=2,p=4,l=24$c29tZXNhbHQ'));

        // invalid salt value
        $this->assertEquals('$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o',
            Enzoic\Hashing::argon2('123456', '$argon2d$v=19$m=10d4,t=ejw,p=2$c2FsdHlzYWx0'));

        $this->assertEquals('$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0IQ$1d6Vh6JVw8dioU9YLncZ63IJWIc',
            Enzoic\Hashing::argon2('123456', 'saltysalt!'));
        $this->assertEquals('$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0Ig$9WEPh4Cz2SBkaA3OKdHUmoTwwmk',
            Enzoic\Hashing::argon2('123456', 'saltysalt"'));
        $this->assertEquals('$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0XA$Dr9QlpppbUzo7/l+/IRA0clFjnA',
            Enzoic\Hashing::argon2('123456', 'saltysalt\\'));
        $this->assertEquals('$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0Jw$I32DNYQfKPQDiiB6NS8CdjmrZmA',
            Enzoic\Hashing::argon2('123456', 'saltysalt\''));
    }
}
