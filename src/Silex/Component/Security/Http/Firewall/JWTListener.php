<?php

namespace Silex\Component\Security\Http\Firewall;

use HttpEncodingException;
use Silex\Component\Security\Core\Encoder\TokenEncoderInterface;
use Silex\Component\Security\Http\Token\JWTToken;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

class JWTListener implements ListenerInterface {

    /**
     * @var TokenStorageInterface
     */
    protected $securityContext;

    /**
     * @var AuthenticationManagerInterface
     */
    protected $authenticationManager;

    /**
     * @var TokenEncoderInterface
     */
    protected $encode;

    /**
     * @var array
     */
    protected $options;

    /**
     * @var string
     */
    protected $providerKey;

    public function __construct(TokenStorageInterface $securityContext,
                                AuthenticationManagerInterface $authenticationManager,
                                TokenEncoderInterface $encoder,
                                array $options,
                                $providerKey)
    {
        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->encode = $encoder;
        $this->options = $options;
        $this->providerKey = $providerKey;
    }

    /**
     * This interface must be implemented by firewall listeners.
     *
     * @param GetResponseEvent $event
     */
    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();
        $requestToken = $this->getToken(
            $request->headers->get($this->options['header_name'], null)
        );

        if (!empty($requestToken)) {

            $username_claim = $this->options['username_claim'];

            try {
                $decoded = $this->encode->decode($requestToken);
                $user = null;
                if (isset($decoded->{$username_claim})) {
                    $user = $decoded->{$username_claim};
                }
                else
                    throw new BadCredentialsException(sprintf("JWT token doesn't have '%s' claim", $username_claim));

                if (!$user) {
                    throw new BadCredentialsException('Invalid username.');
                }

                $token = new JWTToken(
                    $user,
                    $requestToken,
                    (array) $decoded,
                    $this->providerKey
                );

                $authToken = $this->authenticationManager->authenticate($token);
                $this->securityContext->setToken($authToken);

            } catch (HttpEncodingException $e) {
            } catch (\UnexpectedValueException $e) {
            }
        }
    }

    /**
     * Convert token with prefix to normal token
     *
     * @param $requestToken
     *
     * @return string
     */
    protected function getToken($requestToken)
    {
        $prefix = $this->options['token_prefix'];
        if (null === $prefix) {
            return $requestToken;
        }

        if (null === $requestToken) {
            return $requestToken;
        }

        $requestToken = trim(str_replace($prefix, "", $requestToken));

        return $requestToken;
    }
}
