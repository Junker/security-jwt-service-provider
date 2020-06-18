<?php

namespace Silex\Component\Security\Core\Encoder;

use \Firebase\JWT\JWT;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use \Firebase\JWT\JWT;

class JWTEncoder implements TokenEncoderInterface
{

    /**
     * Secret key for tokens encode and decode
     *
     * @var string
     */
    private $secretKey;

    /**
     * Life time tokens
     *
     * @var int
     */
    private $lifeTime;

    private $algorithm;

    public function __construct(string $secretKey, int $lifeTime, string $algorithm, array $options)
    {
        $this->secretKey = $secretKey;
        $this->lifeTime = $lifeTime;
        $this->algorithm = $algorithm;
        $this->options = $options;
    }

    /**
     * Encoded data
     *
     * @param mixed $data
     *
     * @return string
     */
    public function encode($data)
    {
        $options = $this->options;

        $data['exp'] = time() + $this->lifeTime;

        if ($options['add_issued_at'] ?? false)
            $data['iat'] = time();

        if ($options['not_before'] ?? false)
            $data['nbf'] = is_function($options['not_before']) ? $otions['not_before']() : $otions['not_before'];

        if ($options['identifier'] ?? false)
            $data['jti'] = is_function($options['identifier']) ? $otions['identifier']() : $options['identifier'];

        if ($options['subject'] ?? false)
            $data['sub'] = is_function($options['subject']) ? $otions['subject']() : $options['subject'];

        if ($options['audience'] ?? false)
            $data['aud'] = is_function($options['audience']) ? $otions['audience']() : $options['audience'];

        if ($options['issuer'] ?? false)
            $data['iss'] = $otions['issuer'];

        return JWT::encode($data, $this->secretKey, $this->algorithm);
    }

    /**
     * Token for decoding
     *
     * @param string $token
     * @return array
     *
     * @throws AccessDeniedException
     */
    public function decode($token)
    {
        try {
            $data = JWT::decode($token, $this->secretKey, [$this->algorithm]);
        } catch (\UnexpectedValueException $e) {
            throw new \UnexpectedValueException($e->getMessage());
        } catch (\DomainException $e) {
            throw new \UnexpectedValueException($e->getMessage());
        }

        return $data;
    }
}
