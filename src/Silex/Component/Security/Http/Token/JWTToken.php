<?php

namespace Silex\Component\Security\Http\Token;


use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class JWTToken extends AbstractToken implements TokenInterface
{
    /**
     * @var string token context from JWT tokens
     */
    protected $tokenContext;

    /**
     * @var string username claim for JWT token
     */
    protected $usernameClaim;

    protected $payload;

    /**
     * Constructor.
     *
     * @param string|object            $user        The user
     * @param mixed                    $context The user credentials
     * @param array                    $context The payload
     * @param string                   $providerKey The provider key
     * @param RoleInterface[]|string[] $roles       An array of roles
     */
    public function __construct($user, $context, array $payload, string $providerKey, array $roles = array()) {
        parent::__construct($roles);
        $this->setUser($user);
        $this->credentials = $context;
        $this->payload = $payload;
        $this->providerKey = $providerKey;

        parent::setAuthenticated(count($roles) > 0);
    }

    /**
     * Returns the user credentials.
     *
     * @return mixed The user credentials
     */
    public function getCredentials()
    {
        return $this->credentials;
    }

    public function getPayload()
    {
        return $this->payload;
    }

}
