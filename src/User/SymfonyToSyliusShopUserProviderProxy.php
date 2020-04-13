<?php

declare(strict_types=1);
/**
 * Copyright (C) 2019 Brille24 GmbH.
 * This package (including this file) was released under the terms of the GPL-3.0.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/> or send me a mail so i can send you a copy.
 *
 * @license GPL-3.0
 * @author Gerrit Addiks <gerrit.addiks@brille24.de>
 * @author Joe Nilson <joenilson@gmail.com>
 */

namespace Brille24\SyliusLdapPlugin\User;

use Brille24\SyliusLdapPlugin\Ldap\LdapAttributeFetcherInterface;
use Sylius\Bundle\UserBundle\Provider\AbstractUserProvider;
use Sylius\Bundle\UserBundle\Provider\UserProviderInterface as SyliusUserProviderInterface;
use Sylius\Component\Core\Model\CustomerInterface;
use Sylius\Component\Core\Model\ShopUserInterface;
use Sylius\Component\Resource\Factory\FactoryInterface;
use Sylius\Component\User\Model\UserInterface as SyliusUserInterface;
use Symfony\Component\PropertyAccess\PropertyAccessorInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface as SymfonyUserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface as SymfonyUserProviderInterface;
use Symfony\Component\DependencyInjection\ContainerInterface as SymfonyContainerInterface;
use Webmozart\Assert\Assert;

final class SymfonyToSyliusShopUserProviderProxy implements SyliusUserProviderInterface
{
    /**
     * @var SymfonyUserProviderInterface
     */
    private $ldapUserProvider;

    /**
     * @var AbstractUserProvider
     */
    private $customerUserProvider;
    
    /**
     * @var AbstractUserProvider
     */
    private $shopUserProvider;

    /**
     * @var LdapAttributeFetcherInterface
     */
    private $attributeFetcher;

    /**
     * @var PropertyAccessorInterface
     */
    private $propertyAccessor;

    /**
     * @var FactoryInterface
     */
    private $customerUserFactory;
    
    /**
     * @var FactoryInterface
     */
    private $shopUserFactory;
    
    /**
     * @var ContainerInterface
     */
    private $container;
    
    public function __construct(
        SymfonyUserProviderInterface $ldapUserProvider, 
        AbstractUserProvider $customerUserProvider, 
        PropertyAccessorInterface $propertyAccessor, 
        LdapAttributeFetcherInterface $attributeFetcher, 
        FactoryInterface $customerUserFactory, 
        FactoryInterface $shopUserFactory, 
        SymfonyContainerInterface $container
    ) { 
        $this->ldapUserProvider = $ldapUserProvider;
        $this->customerUserProvider = $customerUserProvider;
        $this->attributeFetcher = $attributeFetcher;
        $this->propertyAccessor = $propertyAccessor;
        $this->customerUserFactory = $customerUserFactory;
        $this->shopUserFactory = $shopUserFactory;
        $this->container = $container;
    }

    public function loadUserByUsername($username): SyliusUserInterface
    {
        /** @var SymfonyUserInterface $symfonyLdapUser */
        $symfonyLdapUser = $this->ldapUserProvider->loadUserByUsername($username);
        $syliusLdapUser = $this->convertSymfonyToSyliusUser($symfonyLdapUser);
        try {
            /** @var SyliusUserInterface $syliusUser */
            $syliusUser = $this->customerUserProvider->loadUserByUsername($username);
        } catch (UsernameNotFoundException $notFoundException) {
            return $syliusLdapUser;
        }

        $this->synchroniseUsers($syliusLdapUser, $syliusUser);

        return $syliusUser;
    }

    public function refreshUser(SymfonyUserInterface $user): SymfonyUserInterface
    {
        /** @var SymfonyUserInterface $symfonyLdapUser */
        $symfonyLdapUser = $this->ldapUserProvider->refreshUser($user);

        /** @var SyliusUserInterface $syliusLdapUser */
        $syliusLdapUser = $this->convertSymfonyToSyliusUser($symfonyLdapUser);

        // Non-sylius-users (e.g.: symfony-users) are immutable and cannot be updated / synced.
        Assert::isInstanceOf($user, SyliusUserInterface::class);

        $this->synchroniseUsers($syliusLdapUser, $user);

        return $user;
    }

    public function supportsClass($class): bool
    {
        return $this->ldapUserProvider->supportsClass($class);
    }

    private function convertSymfonyToSyliusUser(SymfonyUserInterface $symfonyUser): SyliusUserInterface
    {
        /** @var array<string, string> $ldapAttributes */
        $ldapAttributes = $this->attributeFetcher->fetchAttributesForUser($symfonyUser);
        $locked = $this->attributeFetcher->toBool($ldapAttributes['locked']);
        
        /** @var CustomerInterface $customer */
        $customer = $this->createCustomerUser($ldapAttributes);
        $syliusUser = $this->container->get('sylius.repository.shop_user')->findOneBy(['username' => $symfonyUser->getUsername()]);
        if(!$syliusUser) {
            /** @var ShopUserInterface $syliusUser */
            $syliusUser = $this->shopUserFactory->createNew();
            $syliusUser->setCustomer($customer);
            $syliusUser->setEmail($ldapAttributes['email']);
            $syliusUser->setUsername($symfonyUser->getUsername());
            $syliusUser->setLocked($locked);
            $syliusUser->setEnabled(!$locked);
            $syliusUser->setPlainPassword('ldap');
            $syliusUser->setExpiresAt($ldapAttributes['expires_at']);
            $syliusUser->setLastLogin($this->attributeFetcher->toDateTime($ldapAttributes['last_login']));
            $syliusUser->setVerifiedAt($this->attributeFetcher->toDateTime($ldapAttributes['verified_at']));
            $syliusUser->setEmailCanonical($ldapAttributes['email_canonical']);
            $syliusUser->setUsernameCanonical($ldapAttributes['username_canonical']);
            $syliusUser->setCredentialsExpireAt($this->attributeFetcher->toDateTime($ldapAttributes['credentials_expire_at']));
            $this->convertSymfonyToSyliusUser($symfonyUser);
        }
        return $syliusUser;
    }
    
    private function createCustomerUser($ldapAttributes): CustomerInterface
    {
        $customer = $this->container->get('sylius.repository.customer')->findOneBy(['email' => $ldapAttributes['email']]);
        if(!$customer) {
        /** @var CustomerInterface $newCustomer */
            $newCustomer = $this->container->get('sylius.factory.customer')->createNew();
            $newCustomer->setEmail($ldapAttributes['email']);
            $newCustomer->setFirstName($ldapAttributes['first_name']);
            $newCustomer->setLastName($ldapAttributes['last_name']);
            $this->container->get('sylius.repository.customer')->add($newCustomer);
            $this->createCustomerUser($ldapAttributes);
        }
        return $customer;
    }

    private function synchroniseUsers(
        SyliusUserInterface $sourceUser,
        SyliusUserInterface $targetUser
    ): void {
        $attributesToSync = [
            'email',
            'expiresAt',
            'lastLogin',
            'enabled',
            'verifiedAt',
            'emailCanonical',
            'username',
            'usernameCanonical',
            'credentialsExpireAt',
        ];

        if ($targetUser instanceof CustomerInterface && $sourceUser instanceof CustomerInterface) {
            $attributesToSync[] = 'lastName';
            $attributesToSync[] = 'firstName';
            $attributesToSync[] = 'localeCode';
        }

//        foreach ($attributesToSync as $attributeToSync) {
//            $value = $this->propertyAccessor->getValue($sourceUser, $attributeToSync);
//            $this->propertyAccessor->setValue($targetUser, $attributeToSync, $value);
//        }
    }
}
