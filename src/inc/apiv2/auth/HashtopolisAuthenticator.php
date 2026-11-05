<?php


/* Authentication middleware for token retrival */

namespace Hashtopolis\inc\apiv2\auth;

use Exception;
use Hashtopolis\inc\defines\DLogEntry;
use Hashtopolis\inc\defines\DLogEntryIssuer;
use Hashtopolis\inc\Encryption;
use Hashtopolis\dba\Factory;
use Hashtopolis\dba\models\User;
use Hashtopolis\dba\QueryFilter;
use Hashtopolis\inc\apiv2\auth\oidc\OidcConfig;
use Hashtopolis\inc\apiv2\error\HttpForbidden;
use Tuupola\Middleware\HttpBasicAuthentication\AuthenticatorInterface;
use Hashtopolis\inc\Util;

class HashtopolisAuthenticator implements AuthenticatorInterface {
  /**
   * @throws HttpForbidden
   * @throws Exception
   */
  public function __invoke(array $arguments): bool {
    OidcConfig::get()->assertLocalLoginAllowed();
    return self::verifyCredentials($arguments["user"], $arguments["password"]) !== null;
  }
  
  /**
   * Verifies a username and password. Returns the user on success, null on unknown user or wrong password.
   * @throws HttpForbidden when the user is disabled
   * @throws Exception
   */
  public static function verifyCredentials(string $username, string $password): ?User {
    $filter = new QueryFilter(User::USERNAME, $username, "=");
    
    $user = Factory::getUserFactory()->filter([Factory::FILTER => $filter], true);
    if ($user === null) {
      return null;
    }
    
    if ($user->getIsValid() != 1) {
      throw new HttpForbidden("Cannot log in. Please contact your administrator for further information");
    }
    else if (!Encryption::passwordVerify($password, $user->getPasswordSalt(), $user->getPasswordHash())) {
      Util::createLogEntry(DLogEntryIssuer::USER, $user->getId(), DLogEntry::WARN, "Failed login attempt due to wrong password!");
      return null;
    }
    Factory::getUserFactory()->set($user, User::LAST_LOGIN_DATE, time());
    return $user;
  }
}