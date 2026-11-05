<?php

namespace Hashtopolis\inc\utils;

use Exception;
use Hashtopolis\dba\Factory;
use Hashtopolis\dba\models\OidcIdentity;
use Hashtopolis\dba\OrderFilter;
use Hashtopolis\dba\QueryFilter;
use Hashtopolis\dba\UpdateSet;
use Hashtopolis\inc\apiv2\auth\oidc\OidcAlreadyLinkedException;
use Hashtopolis\inc\apiv2\auth\oidc\OidcClaims;
use PDOException;

/**
 * Links external OIDC identities, keyed by (issuer, subject), to local users.
 *
 * Email addresses and display names are never used to match an identity.
 */
class OidcIdentityUtils {
  /**
   * Finds the identity with exactly this issuer and subject.
   *
   * @throws Exception
   */
  public static function find(string $issuer, string $subject): ?OidcIdentity {
    $identity = Factory::getOidcIdentityFactory()->filter([
      Factory::FILTER => [
        new QueryFilter(OidcIdentity::ISSUER, $issuer, "="),
        new QueryFilter(OidcIdentity::SUBJECT, $subject, "=")
      ]
    ], true);
    // Defence in depth in case a database collation is looser than the unique key expects
    if (!$identity instanceof OidcIdentity || $identity->getIssuer() !== $issuer || $identity->getSubject() !== $subject) {
      return null;
    }
    return $identity;
  }
  
  /**
   * Links the identity to the user. Returns the existing row if the user already has it.
   *
   * @throws OidcAlreadyLinkedException if another user owns the identity
   * @throws Exception
   */
  public static function link(int $userId, OidcClaims $claims): OidcIdentity {
    $existing = self::find($claims->issuer, $claims->subject);
    if ($existing !== null) {
      return self::sameOwnerOrThrow($existing, $userId);
    }
    
    $identity = new OidcIdentity(null, $userId, $claims->issuer, $claims->subject, $claims->label, time(), null);
    try {
      $saved = Factory::getOidcIdentityFactory()->save($identity);
    }
    catch (PDOException $e) {
      return self::resolveInsertFailure($userId, $claims, $e);
    }
    if (!$saved instanceof OidcIdentity) {
      throw new Exception("Could not store the OIDC identity");
    }
    return $saved;
  }
  
  /**
   * Handles a failed insert. If it was a unique-key collision (a concurrent insert won), the row
   * is re-read: the same user gets it back, another user gets OidcAlreadyLinkedException. Any
   * other failure is rethrown.
   *
   * @internal public only so tests can reach it
   * @throws OidcAlreadyLinkedException
   * @throws PDOException
   * @throws Exception
   */
  public static function resolveInsertFailure(int $userId, OidcClaims $claims, PDOException $e): OidcIdentity {
    $sqlState = (string)($e->errorInfo[0] ?? $e->getCode());
    if (!str_starts_with($sqlState, '23')) {
      throw $e;
    }
    $existing = self::find($claims->issuer, $claims->subject);
    if ($existing === null) {
      throw $e;
    }
    return self::sameOwnerOrThrow($existing, $userId);
  }
  
  /**
   * @throws OidcAlreadyLinkedException
   */
  private static function sameOwnerOrThrow(OidcIdentity $identity, int $userId): OidcIdentity {
    if ($identity->getUserId() !== $userId) {
      throw new OidcAlreadyLinkedException("This identity is already linked to another user");
    }
    return $identity;
  }
  
  /**
   * @return OidcIdentity[] the user's identities, oldest first
   * @throws Exception
   */
  public static function listForUser(int $userId): array {
    return Factory::getOidcIdentityFactory()->filter([
      Factory::FILTER => new QueryFilter(OidcIdentity::USER_ID, $userId, "="),
      Factory::ORDER => [
        new OrderFilter(OidcIdentity::CREATED_AT, "ASC"),
        new OrderFilter(OidcIdentity::OIDC_IDENTITY_ID, "ASC")
      ]
    ]);
  }
  
  /**
   * Removes an identity, but only if it belongs to the given user.
   *
   * @return bool false if the identity does not exist or belongs to someone else
   * @throws Exception
   */
  public static function unlink(int $userId, int $identityId): bool {
    $stmt = Factory::getOidcIdentityFactory()->massDeletion([
      Factory::FILTER => [
        new QueryFilter(OidcIdentity::OIDC_IDENTITY_ID, $identityId, "="),
        new QueryFilter(OidcIdentity::USER_ID, $userId, "=")
      ]
    ]);
    return $stmt->rowCount() > 0;
  }
  
  /**
   * Records that the identity was just used to sign in.
   *
   * @throws Exception
   */
  public static function touch(OidcIdentity $identity): void {
    $now = time();
    Factory::getOidcIdentityFactory()->massUpdate([
      Factory::FILTER => new QueryFilter(OidcIdentity::OIDC_IDENTITY_ID, $identity->getId(), "="),
      Factory::UPDATE => new UpdateSet(OidcIdentity::LAST_USED_AT, $now)
    ]);
    $identity->setLastUsedAt($now);
  }
}
