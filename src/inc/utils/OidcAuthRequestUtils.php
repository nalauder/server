<?php

namespace Hashtopolis\inc\utils;

use Exception;
use Hashtopolis\dba\Factory;
use Hashtopolis\dba\models\OidcAuthRequest;
use Hashtopolis\dba\QueryFilter;
use Hashtopolis\dba\UpdateSet;
use Hashtopolis\inc\apiv2\auth\oidc\OidcClaims;

/**
 * Creating, looking up and consuming the short-lived state of an OIDC sign-in in progress.
 *
 * The state value itself only ever exists in the redirect to the provider and in the browser's
 * cookie; the database stores its SHA-256 hash, so a leaked table cannot be replayed. A request is
 * single use: consuming it marks it used with a conditional update, so concurrent callbacks with
 * the same state elect exactly one winner.
 */
class OidcAuthRequestUtils {
  /** How long a request stays valid, in seconds. */
  const LIFETIME = 600;
  
  const PURPOSE_LOGIN = 'login';
  const PURPOSE_LINK = 'link';
  const PURPOSE_PENDING_LINK = 'pending_link';
  
  /**
   * Only the hash of a state is stored, so a copy of the table cannot be used to complete a login.
   *
   * @param string $state
   * @return string
   */
  private static function hashState(string $state): string {
    return hash("sha256", $state);
  }
  
  /**
   * Base64 with the URL-safe alphabet and no padding, as PKCE requires.
   *
   * @param string $raw
   * @return string
   */
  private static function base64Url(string $raw): string {
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
  }
  
  /**
   * The PKCE S256 code challenge for a verifier (RFC 7636).
   */
  public static function codeChallenge(string $verifier): string {
    return self::base64Url(hash("sha256", $verifier, true));
  }
  
  /**
   * Removes expired and used requests, so nothing outlives its purpose. Called wherever a request is
   * created or finished, as the table holds identity data while a request is pending.
   */
  public static function purgeStale(): void {
    Factory::getOidcAuthRequestFactory()->massDeletion([
      Factory::FILTER => new QueryFilter(OidcAuthRequest::EXPIRES_AT, time(), "<")
    ]);
    Factory::getOidcAuthRequestFactory()->massDeletion([
      Factory::FILTER => new QueryFilter(OidcAuthRequest::USED_AT, null, "<>")
    ]);
  }
  
  /**
   * Starts a request and removes expired and used ones, so nothing outlives its purpose.
   *
   * @param string $purpose one of the PURPOSE_ constants
   * @param string $returnTo frontend origin, already checked against the trusted list by the caller
   * @param int|null $userId the user a link request belongs to
   * @param OidcClaims|null $pending the verified identity a pending_link request carries
   * @return array{state: string, request: OidcAuthRequest} the plain state is returned only here
   * @throws Exception
   */
  public static function create(string $purpose, string $returnTo, ?int $userId = null, ?OidcClaims $pending = null): array {
    self::purgeStale();
    $now = time();
    
    $state = bin2hex(random_bytes(32));
    $isPending = $purpose === self::PURPOSE_PENDING_LINK;
    $request = new OidcAuthRequest(
      null,
      self::hashState($state),
      $purpose,
      $userId,
      $isPending ? null : self::base64Url(random_bytes(48)),
      bin2hex(random_bytes(16)),
      $returnTo,
      $pending?->issuer,
      $pending?->subject,
      $pending?->label,
      $now + self::LIFETIME,
      null
    );
    $request = Factory::getOidcAuthRequestFactory()->save($request);
    if (!$request instanceof OidcAuthRequest) {
      throw new Exception("Could not store the OIDC auth request");
    }
    return ['state' => $state, 'request' => $request];
  }
  
  /**
   * Looks up a usable request without using it up. Returns null if it is missing, of another
   * purpose, expired or already used.
   */
  public static function peek(string $state, string $purpose): ?OidcAuthRequest {
    try {
      $request = Factory::getOidcAuthRequestFactory()->filter([
        Factory::FILTER => new QueryFilter(OidcAuthRequest::STATE_HASH, self::hashState($state), "=")
      ], true);
    }
    catch (Exception) {
      return null;
    }
    if (!$request instanceof OidcAuthRequest
      || $request->getPurpose() !== $purpose
      || $request->getUsedAt() !== null
      || $request->getExpiresAt() < time()) {
      return null;
    }
    return $request;
  }
  
  /**
   * Looks up a usable request and uses it up. Of several concurrent callers only one gets the row.
   * The returned object's in-memory usedAt is not refreshed and still reads null.
   */
  public static function consume(string $state, string $purpose): ?OidcAuthRequest {
    $request = self::peek($state, $purpose);
    if ($request === null || !self::markUsed($request)) {
      return null;
    }
    return $request;
  }
  
  /**
   * Marks a request used, but only while it is still unused.
   *
   * The condition lives in the UPDATE rather than in a preceding read, so the database elects the
   * winner when callbacks arrive together (same approach as RefreshTokenUtils::claim).
   *
   * The same update scrubs the row's secrets and identity data (PKCE verifier, nonce, issuer,
   * subject, label), so a used row holds nothing sensitive while it waits to be purged. The
   * caller's in-memory object keeps its values so the flow can finish.
   *
   * @return bool whether this caller is the one that used it
   */
  public static function markUsed(OidcAuthRequest $request): bool {
    try {
      return Factory::getOidcAuthRequestFactory()->compareAndSet(
        $request,
        [new QueryFilter(OidcAuthRequest::USED_AT, null, "=")],
        [
          new UpdateSet(OidcAuthRequest::USED_AT, time()),
          new UpdateSet(OidcAuthRequest::CODE_VERIFIER, null),
          new UpdateSet(OidcAuthRequest::NONCE, null),
          new UpdateSet(OidcAuthRequest::ISSUER, null),
          new UpdateSet(OidcAuthRequest::SUBJECT, null),
          new UpdateSet(OidcAuthRequest::LABEL, null),
        ]
      );
    }
    catch (Exception) {
      return false;
    }
  }
}
