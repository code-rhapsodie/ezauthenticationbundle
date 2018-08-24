<?php

namespace CodeRhapsodie\EzAuthenticationBundle\Security\Guard\Authenticator;

use eZ\Publish\API\Repository\Repository;
use eZ\Publish\Core\Base\Exceptions\NotFoundException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Symfony\Component\Security\Guard\Authenticator\AbstractFormLoginAuthenticator;

class EzFormLoginAuthenticator extends AbstractFormLoginAuthenticator
{
    /**
     * @var Repository
     */
    private $repository;

    /**
     * @var string
     */
    private $loginUrl;

    /**
     * @var string
     */
    private $defaultSuccessRedirectUrl;

    /**
     * @param Repository $repository
     * @param string     $loginUrl
     * @param string     $defaultSuccessRedirectUrl
     */
    public function __construct(Repository $repository, $loginUrl, $defaultSuccessRedirectUrl)
    {
        $this->repository = $repository;
        $this->loginUrl = $loginUrl;
        $this->defaultSuccessRedirectUrl = $defaultSuccessRedirectUrl;
    }

    /**
     * {@inheritdoc}
     */
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

    /**
     * {@inheritdoc}
     */
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

    /**
     * {@inheritdoc}
     */
    protected function getLoginUrl()
    {
        return $this->loginUrl;
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultSuccessRedirectUrl()
    {
        return $this->defaultSuccessRedirectUrl;
    }


}