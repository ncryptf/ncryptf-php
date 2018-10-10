<?php declare(strict_types=1);

namespace ncryptf\Tests\mock;

use ncryptf\Token;
use ncryptf\middleware\AbstractAuthentication;

final class Authentication extends AbstractAuthentication
{
    protected function getTokenFromAccessToken(string $accessToken) :? Token
    {
        // Return a fixed token
        return new Token(
            'x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J',
            'LRSEe5zHb1aq20Hr9te2sQF8sLReSkO8bS1eD/9LDM8',
            \base64_decode('f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k='),
            \base64_decode('7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw=='),
            \strtotime('+4 hours')
        );
    }

    protected function getUserFromToken(Token $token)
    {
        return [
            'id' => 1
        ];
    }
}
