<?php

namespace CodeRhapsodie\EzAuthenticationBundle\Security;

use eZ\Publish\API\Repository\Repository;
use eZ\Publish\Core\Base\Exceptions\NotFoundException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

class EzLoginAuthenticator extends AbstractGuardAuthenticator
{
    /**
     * @var Repository
     */
    private $repository;

    public function __construct(Repository $repository)
    {
        $this->repository = $repository;
    }

    public function getCredentials(Request $request)
    {
        if ($request->request->has('_username')) {
            return array(
                'username' => $request->request->get('_username'),
                'password' => $request->request->get('_password'),
            );
        } else {
            return;
        }
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        return $userProvider->loadUserByUsername($credentials['username']);
    }

    /**
     * @param mixed                                                    $credentials
     * @param UserInterface|\eZ\Publish\Core\MVC\Symfony\Security\User $user
     *
     * @return bool
     * @throws \Exception
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        try {
            if ($this->repository->getUserService()->loadUserByCredentials(
                $user->getAPIUser()->login,
                $credentials['password'])) {
                $this->repository->setCurrentUser($user->getAPIUser());
            }

            return true;
        } catch (NotFoundException $e) {
            throw new AuthenticationException('Invalid credentials', 0, $e);
        } catch (\Exception $e) {
            throw $e;
        }
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return new RedirectResponse('/login');
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
    }

    public function supportsRememberMe()
    {
        return true;
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        return new RedirectResponse('/login');
    }
}