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
declare( strict_types=1 );

namespace Novactive\eZLDAPAuthenticator\User\Converter;

use Exception;
use eZ\Publish\API\Repository\Exceptions\NotFoundException;
use eZ\Publish\API\Repository\Repository;
use eZ\Publish\API\Repository\Values\Content\Content;
use eZ\Publish\API\Repository\Values\Content\LocationQuery;
use eZ\Publish\API\Repository\Values\Content\Query;
use eZ\Publish\API\Repository\Values\Content\Query\Criterion\Operator;
use eZ\Publish\API\Repository\Values\User\User as EzApiUser;
use eZ\Publish\API\Repository\Values\User\UserGroup;
use eZ\Publish\Core\MVC\ConfigResolverInterface;
use Novactive\eZLDAPAuthenticator\User\EzLdapUser;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\OptionsResolver\OptionsResolver;

class LdapEntryConverter
{
    public const EMAIL_ATTR_OPTION = 'email_attr';
    public const ATTRIBUTES_OPTION = 'attributes';
    public const ADMIN_USER_ID_OPTION = 'admin_user_id';
    public const USER_GROUP_ID_OPTION = 'user_group_id';
    public const USER_GROUP_ATTR = 'user_group_attr';
    public const GROUP_NAME_ATTR = 'group_name_attr';

    /** @var Repository */
    protected $repository;

    /** @var ConfigResolverInterface */
    protected $configResolver;

    /**
     * @var array
     */
    protected $options;

    /**
     * LdapEntryConverter constructor.
     */
    public function __construct( array $options = [] )
    {
        $this->setOptions( $options );
    }

    public function setOptions( array $options ): void
    {
        $resolver = new OptionsResolver();
        $this->configureOptions( $resolver );
        $this->options = $resolver->resolve( $options );
    }

    public function configureOptions( OptionsResolver $resolver ): void
    {
        $resolver->setDefaults(
            [
                self::ATTRIBUTES_OPTION => [],
                self::USER_GROUP_ATTR => null,
                self::GROUP_NAME_ATTR => null,
            ]
        );
        $resolver->setRequired( self::EMAIL_ATTR_OPTION );
        $resolver->setRequired( self::ADMIN_USER_ID_OPTION );
        $resolver->setRequired( self::USER_GROUP_ID_OPTION );
        $resolver->setAllowedTypes( self::EMAIL_ATTR_OPTION, 'string' );
        $resolver->setAllowedTypes( self::ATTRIBUTES_OPTION, 'array' );
        $resolver->setAllowedTypes( self::ADMIN_USER_ID_OPTION, 'int' );
        $resolver->setAllowedTypes( self::USER_GROUP_ID_OPTION, 'int' );
        $resolver->setAllowedTypes( self::USER_GROUP_ATTR, 'string' );
        $resolver->setAllowedTypes( self::GROUP_NAME_ATTR, 'string' );
    }

    /**
     * @return mixed
     */
    public function getOption( $name, $defaultValue = null )
    {
        return $this->options[$name] ?? $defaultValue;
    }

    /**
     * @required
     */
    public function setRepository( Repository $repository ): void
    {
        $this->repository = $repository;
    }

    /**
     * @required
     */
    public function setConfigResolver( ConfigResolverInterface $configResolver ): void
    {
        $this->configResolver = $configResolver;
    }

    public function getEntryGroups( Entry $entry ): array
    {
        return $entry->getAttribute( $this->options[self::USER_GROUP_ATTR] );
    }

    /**
     * @throws Exception
     */
    public function convert( string $username, Entry $entry, array $groups = [] ): EzLdapUser
    {
        $attributes = [];
        $attributesMap = $this->options[self::ATTRIBUTES_OPTION];
        foreach ( $attributesMap as $attributeIdentifier => $attributeValueIdentifier )
        {
            $attributes[$attributeIdentifier] = $this->getEntryAttribute( $entry, $attributeValueIdentifier );
        }
        $email = (string)$this->getEntryAttribute( $entry, $this->options[self::EMAIL_ATTR_OPTION] );

        return new EzLdapUser( $username, $email, $attributes, [ 'ROLE_USER' ], $groups );
    }

    /**
     * @return array|mixed|null
     */
    protected function getEntryAttribute( Entry $entry, string $attributeName )
    {
        $attributeValue = $entry->getAttribute( $attributeName );
        if ( is_array( $attributeValue ) && 1 === count( $attributeValue ) )
        {
            return reset( $attributeValue );
        }

        return $attributeValue;
    }

    /**
     * @throws Exception
     */
    public function convertToEzUser(
        string $username,
        string $email,
        array $attributes,
        array $groupsName = []
    ): EzApiUser
    {
        $userGroups = $this->convertToEzGroups( $groupsName );
        $userService = $this->repository->getUserService();

        try
        {
            $eZUser = $userService->loadUserByLogin( $username );
            $this->repository->sudo(
                function ( Repository $repository ) use ($eZUser, $userGroups) {
                    $userService = $repository->getUserService();
                    $existingUserGroups = $userService->loadUserGroupsOfUser( $eZUser );
                    $userGroupsToUnassign = [];
                    foreach ( $existingUserGroups as $existingUserGroup )
                    {
                        if ( !isset( $userGroups[$existingUserGroup->id] ) )
                        {
                            $userGroupsToUnassign[] = $existingUserGroup;
                        }
                        else
                        {
                            unset( $userGroups[$existingUserGroup->id] );
                        }
                    }
                    foreach ( $userGroups as $userGroup )
                    {
                        $userService->assignUserToUserGroup( $eZUser, $userGroup );
                    }
                    foreach ( $userGroupsToUnassign as $userGroup )
                    {
                        $userService->unAssignUserFromUserGroup( $eZUser, $userGroup );
                    }
                }
            );
        }
        catch ( NotFoundException $exception )
        {
            $mainLanguage = $this->getMainLanguage();
            $eZUserCreateStruct = $userService->newUserCreateStruct(
                $username,
                $email,
                md5( uniqid( EzLdapUser::class, true ) ),
                $mainLanguage
            );

            foreach ( $attributes as $attributeIdentifier => $attributeValue )
            {
                $eZUserCreateStruct->setField( $attributeIdentifier, $attributeValue );
            }
            $eZUserCreateStruct->enabled = true;
            $eZUserCreateStruct->ownerId = $this->options[self::ADMIN_USER_ID_OPTION];

            // Create new user under 'admin' user
            $eZUser = $this->repository->sudo(
                function ( Repository $repository ) use ( $eZUserCreateStruct, $userGroups ) {
                    $userService = $repository->getUserService();

                    if ( empty( $userGroups ) )
                    {
                        $userGroups[] = $userService->loadUserGroup(
                            $this->options[self::USER_GROUP_ID_OPTION]
                        );
                    }

                    return $userService->createUser( $eZUserCreateStruct, $userGroups );
                }
            );
        }

        return $eZUser;
    }

    /**
     * @param array $groupsName
     * @return UserGroup[]
     * @throws Exception
     */
    public function convertToEzGroups( array $groupsName ): array
    {
        return $this->repository->sudo(
            function ( Repository $repository ) use ( $groupsName ) {
                $mainLanguage = $this->getMainLanguage();
                $baseUserGroupCreateStruct = $this->repository->getUserService()->newUserGroupCreateStruct(
                    $mainLanguage
                );

                $query = new Query();
                $query->filter = new Query\Criterion\LogicalAnd(
                    [
                        new Query\Criterion\ContentTypeId( $baseUserGroupCreateStruct->contentType->id ),
                        new Query\Criterion\Field( 'name', Operator::IN, $groupsName )
                    ]
                );


                $searchService = $repository->getSearchService();
                $searchResults = $searchService->findContent( $query );

                $groups = [];
                $foundGroupsName = [];
                foreach ( $searchResults->searchHits as $searchHit )
                {
                    /** @var Content $content */
                    $content = $searchHit->valueObject;
                    $foundGroupsName[] = $content->getName( $mainLanguage );
                    $groups[$content->id] = $repository->getUserService()->loadUserGroup( $content->id );

                }

                $misingGroupsName = array_udiff( $groupsName, $foundGroupsName, 'strcasecmp' );
                if ( !empty( $misingGroupsName ) )
                {
                    $parentGroup = $repository->getUserService()->loadUserGroup(
                        $this->options[self::USER_GROUP_ID_OPTION]
                    );
                    foreach ( $misingGroupsName as $misingGroupName )
                    {
                        $userGroupCreateStruct = clone $baseUserGroupCreateStruct;
                        $userGroupCreateStruct->setField( 'name', ucfirst( $misingGroupName ) );

                        $userGroup = $repository->getUserService()->createUserGroup(
                            $userGroupCreateStruct,
                            $parentGroup
                        );
                        $groups[$userGroup->id] = $userGroup;
                    }
                }
                return $groups;
            }
        );
    }

    protected function getMainLanguage(): string
    {
        $languages = $this->configResolver->getParameter( 'languages' );
        return array_shift( $languages );
    }
}
