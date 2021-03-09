<?php

/**
 * NovaeZLDAPAuthenticator Bundle.
 *
 * @package   Novactive\Bundle\eZLDAPAuthenticatorBundle
 *
 * @author    Novactive
 * @copyright 2019 Novactive
 * @license   https://github.com/Novactive/NovaeZLdapAuthenticatorBundle/blob/master/LICENSE MIT Licence
 */

declare(strict_types=1);

namespace Novactive\eZLDAPAuthenticator\User\Provider;

use Exception;
use eZ\Publish\API\Repository\Values\User\User as EzApiUser;
use Novactive\eZLDAPAuthenticator\User\Converter\LdapEntryConverter;
use Novactive\eZLDAPAuthenticator\User\EzLdapUser;
use Psr\Log\LoggerInterface;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Ldap\LdapInterface;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\LdapUserProvider;

class EzLdapUserProvider extends LdapUserProvider
{
    /** @var LdapEntryConverter */
    protected $ldapEntryConverter;

    /** @var LoggerInterface */
    protected $logger;

    /** @var LdapInterface */
    protected $ldap;

    /** @var string|null */
    protected $searchDn;

    /** @var string|null */
    protected $searchPassword;

    /** @var string|null */
    protected $baseDn;

    /** @var string|null */
    protected $uidKey;

    /** @var string|null */
    protected $defaultSearch;

    /** @var array */
    protected $attributes;

    /**
     * @param string $baseDn
     * @param string $searchDn
     * @param string $searchPassword
     * @param string $uidKey
     * @param string $filter
     * @param string $passwordAttribute
     * @param array $attributes
     */
    public function __construct(
        LdapInterface $ldap,
        $baseDn,
        $searchDn = null,
        $searchPassword = null,
        array $defaultRoles = [],
        $uidKey = 'sAMAccountName',
        $filter = '({uid_key}={username})',
        $passwordAttribute = null,
        $attributes = [ '*' ]
    ) {
        parent::__construct(
            $ldap,
            $baseDn,
            $searchDn,
            $searchPassword,
            $defaultRoles,
            $uidKey,
            $filter,
            $passwordAttribute
        );
        $this->ldap           = $ldap;
        $this->searchDn       = $searchDn;
        $this->searchPassword = $searchPassword;
        $this->baseDn         = $baseDn;
        $this->uidKey         = $uidKey;
        $this->defaultSearch  = str_replace('{uid_key}', $uidKey, $filter);
        $this->attributes     = $attributes;
    }

    /**
     * @required
     */
    public function setLdapEntryConverter(LdapEntryConverter $ldapEntryConverter): void
    {
        $this->ldapEntryConverter = $ldapEntryConverter;
    }

    /**
     * @required
     */
    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByUsername($username)
    {
        try {
            $this->ldap->bind($this->searchDn, $this->searchPassword);
        } catch (ConnectionException $exception) {
            $message = sprintf(
                'Uncaught PHP Exception %s: "%s" at %s line %s',
                get_class($exception),
                $exception->getMessage(),
                $exception->getFile(),
                $exception->getLine()
            );
            $this->logger->critical($message, [ 'exception' => $exception ]);
        }

        try {
            $this->ldap->bind($this->searchDn, $this->searchPassword);
            $username = $this->ldap->escape($username, '', LdapInterface::ESCAPE_FILTER);
            $query    = str_replace('{username}', $username, $this->defaultSearch);
            $search   = $this->ldap->query($this->baseDn, $query, [ 'filter' => $this->attributes ]);
        } catch (ConnectionException $e) {
            throw new UsernameNotFoundException(sprintf('User "%s" not found.', $username), 0, $e);
        }

        $entries = $search->execute();
        $count   = \count($entries);

        if (!$count) {
            throw new UsernameNotFoundException(sprintf('User "%s" not found.', $username));
        }

        if ($count > 1) {
            throw new UsernameNotFoundException('More than one user found');
        }

        $entry = $entries[0];
        try {
            if (null !== $this->uidKey) {
                $username = $this->getAttributeValue($entry, $this->uidKey);
            }
        } catch (InvalidArgumentException $e) {
            $this->logger->warning($e->getMessage());
        }

        return $this->loadUser($username, $entry);
    }

    /**
     * Fetches a required unique attribute value from an LDAP entry.
     *
     * @param Entry|null $entry
     * @param string $attribute
     */
    private function getAttributeValue(Entry $entry, $attribute)
    {
        if (!$entry->hasAttribute($attribute)) {
            throw new InvalidArgumentException(
                sprintf(
                    'Missing attribute "%s" for user "%s".',
                    $attribute,
                    $entry->getDn()
                )
            );
        }

        $values = $entry->getAttribute($attribute);

        if (1 !== \count($values)) {
            throw new InvalidArgumentException(
                sprintf(
                    'Attribute "%s" has multiple values.',
                    $attribute
                )
            );
        }

        return $values[0];
    }

    /**
     * @param string $username
     *
     * @return EzLdapUser|\Symfony\Component\Security\Core\User\User
     * @throws Exception
     *
     */
    protected function loadUser($username, Entry $entry)
    {
        $entryGroups = $this->ldapEntryConverter->getEntryGroups($entry);
        $groups      = [];
        if (!empty($entryGroups)) {
            foreach ($entryGroups as $entryGroupDn) {
                $groupName = $this->getGroupNameByDN($entryGroupDn);
                if ($groupName !== null) {
                    $groups[] = $groupName;
                }
            }
        }
        return $this->ldapEntryConverter->convert($username, $entry, $groups);
    }

    protected function getGroupNameByDN($domainName)
    {
        $groupNameAttr = $this->ldapEntryConverter->getOption(LdapEntryConverter::GROUP_NAME_ATTR);
        if ($groupNameAttr === null) {
            return null;
        }

        $dnParts                                = ldap_explode_dn($domainName, 0);
        list( $attributeName, $attributeValue ) = explode('=', $dnParts[0]);

        if ($attributeName === $groupNameAttr) { // Read the group name attribute directly from the group DN
            return $attributeValue;
        } else // Read the LDAP group object, get the group name attribute from it
        {
            try {
                $this->ldap->bind($this->searchDn, $this->searchPassword);
                $search = $this->ldap->query($domainName, "($groupNameAttr=*)", [ 'filter' => $groupNameAttr ]);

                $entries = $search->execute();
                $count   = \count($entries);
                if (!$count) {
                    return null;
                }
                /** @var Entry $entry */
                $entry     = $entries[0];
                $groupName = $entry->getAttribute($groupNameAttr);
                if (is_array($groupName)) { // This may be a string or an array of strings, depending on LDAP setup
                    $groupName = $groupName[0];
                } // At least one must exist, since we specified it in the search filter

                return $groupName;
            } catch (ConnectionException $e) {
                return null;
            }
        }

        return $groupName;
    }

    /**
     * @throws Exception
     */
    public function checkEzUser(EzLdapUser $ezLdapUser): EzApiUser
    {
        return $this->ldapEntryConverter->convertToEzUser(
            $ezLdapUser->getUsername(),
            $ezLdapUser->getEmail(),
            $ezLdapUser->getAttributes(),
            $ezLdapUser->getGroups()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class)
    {
        return EzLdapUser::class === $class;
    }
}
