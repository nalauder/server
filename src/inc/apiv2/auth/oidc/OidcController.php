<?php

namespace Hashtopolis\inc\apiv2\auth\oidc;

use Exception;
use Hashtopolis\dba\Factory;
use Hashtopolis\dba\models\OidcAuthRequest;
use Hashtopolis\dba\models\User;
use Hashtopolis\inc\apiv2\auth\HashtopolisAuthenticator;
use Hashtopolis\inc\apiv2\auth\RefreshTokenCookie;
use Hashtopolis\inc\apiv2\error\ErrorHandler;
use Hashtopolis\inc\apiv2\error\HttpConflict;
use Hashtopolis\inc\apiv2\error\HttpError;
use Hashtopolis\inc\apiv2\error\HttpForbidden;
use Hashtopolis\inc\apiv2\error\HttpUnauthorized;
use Hashtopolis\inc\apiv2\error\ResourceNotFoundError;
use Hashtopolis\inc\apiv2\util\CorsHackMiddleware;
use Hashtopolis\inc\defines\DLogEntry;
use Hashtopolis\inc\defines\DLogEntryIssuer;
use Hashtopolis\inc\utils\OidcAuthRequestUtils;
use Hashtopolis\inc\utils\OidcIdentityUtils;
use Hashtopolis\inc\utils\RefreshTokenUtils;
use Hashtopolis\inc\Util;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Throwable;

/**
 * Handlers behind /api/v2/auth/oidc/... (spec §7 and §8). The route file only wires these up, so the
 * handlers can be driven directly with a provider on a fake HTTP client.
 *
 * Browser-facing failures never carry details: the redirect names a reason code and the details go
 * to the log, keyed by user ID where one is known. Tokens and authorization codes are never logged.
 */
class OidcController {
  const REASON_EXPIRED = 'expired';
  const REASON_PROVIDER_ERROR = 'provider_error';
  const REASON_USER_DISABLED = 'user_disabled';
  const REASON_ALREADY_LINKED = 'already_linked';

  /** Log issuer ID for entries that cannot be attributed to a user yet. */
  const LOG_ISSUER_ID = 'oidc';

  private const LOGIN_PAGE = '/auth';
  private const SETTINGS_PAGE = '/account/acc-settings';
  private const SSO_LANDING_PAGE = '/auth/sso';

  public function __construct(
    private readonly OidcConfig $config,
    private readonly OidcProvider $provider
  ) {
  }

  /**
   * GET config. Answers even when SSO is off, so the web UI can learn that it is off.
   */
  public function config(Request $request, Response $response): Response {
    if (!$this->config->isEnabled()) {
      return $this->json($response, ['enabled' => false, 'displayName' => 'SSO', 'localLoginEnabled' => true]);
    }
    return $this->json($response, [
      'enabled' => true,
      'displayName' => $this->config->getDisplayName(),
      'localLoginEnabled' => $this->config->isLocalLoginEnabled(),
    ]);
  }

  /**
   * GET login?returnTo=<origin>. Starts a sign-in and sends the browser to the provider.
   *
   * @throws ResourceNotFoundError
   * @throws HttpError
   * @throws HttpForbidden
   * @throws Exception
   */
  public function login(Request $request, Response $response): Response {
    $this->assertEnabled();
    $raw = $request->getQueryParams()['returnTo'] ?? null;
    $returnTo = is_string($raw) ? CorsHackMiddleware::canonicalTrustedOrigin($raw) : null;
    if ($returnTo === null) {
      throw new HttpError("returnTo must be one of the frontend origins this server trusts");
    }

    $started = $this->startAuthorization(OidcAuthRequestUtils::PURPOSE_LOGIN, $returnTo, null);
    if ($started === null) {
      return $this->redirect($response, $returnTo . self::LOGIN_PAGE . '?sso=error&reason=' . self::REASON_PROVIDER_ERROR);
    }
    return OidcStateCookie::attach($request, $this->redirect($response, $started['url']), $started['state']);
  }

  /**
   * POST link {password}. Starts linking an identity to the signed-in user, after re-checking their password.
   *
   * @throws ResourceNotFoundError
   * @throws HttpError
   * @throws HttpForbidden
   * @throws HttpUnauthorized
   * @throws Exception
   */
  public function link(Request $request, Response $response): Response {
    $this->assertEnabled();
    CorsHackMiddleware::assertNotCrossSite($request);
    $user = $this->currentUser($request);

    $body = $request->getParsedBody();
    $password = is_array($body) ? ($body['password'] ?? null) : null;
    if (!is_string($password) || $password === '') {
      throw new HttpError("password is required");
    }

    $origin = trim($request->getHeaderLine('Origin'));
    $returnTo = $origin !== '' ? CorsHackMiddleware::canonicalTrustedOrigin($origin) : null;
    $returnTo ??= CorsHackMiddleware::defaultFrontendOrigin();
    if ($returnTo === null) {
      throw new HttpError("No frontend origin is configured to return to; set HASHTOPOLIS_FRONTEND_URLS");
    }

    if (HashtopolisAuthenticator::verifyCredentials($user->getUsername(), $password) === null) {
      throw new HttpUnauthorized("Wrong password");
    }

    $started = $this->startAuthorization(OidcAuthRequestUtils::PURPOSE_LINK, $returnTo, $user->getId());
    if ($started === null) {
      throw new HttpError("The single sign-on provider could not be reached", 502);
    }
    return OidcStateCookie::attach($request, $this->json($response, ['authorizeUrl' => $started['url']]), $started['state']);
  }

  /**
   * GET callback. Finishes a login or link request; always answers with a redirect (spec §8), or 400
   * when no request matches and no frontend origin is configured to send the browser to.
   *
   * @throws ResourceNotFoundError
   * @throws Exception
   */
  public function callback(Request $request, Response $response): Response {
    $this->assertEnabled();
    $claimed = null;
    try {
      OidcAuthRequestUtils::purgeStale();
      return $this->finishCallback($request, $response, $claimed);
    }
    catch (Throwable $e) {
      // An unexpected fault (a database error, say) must not leave the browser on a JSON error page
      $isLink = $claimed?->getPurpose() === OidcAuthRequestUtils::PURPOSE_LINK;
      $this->log($isLink ? $claimed->getUserId() : null, DLogEntry::WARN, "Single sign-on callback failed unexpectedly (" . get_class($e) . ")");
      if ($claimed === null) {
        $origin = CorsHackMiddleware::defaultFrontendOrigin();
        if ($origin === null) {
          return ErrorHandler::errorResponse($response, "Single sign-on failed", 400);
        }
        return $this->redirect($response, $origin . self::LOGIN_PAGE . '?sso=error&reason=' . self::REASON_PROVIDER_ERROR);
      }
      $page = (string)$claimed->getReturnTo() . ($isLink ? self::SETTINGS_PAGE : self::LOGIN_PAGE);
      return OidcStateCookie::clear($request, $this->redirect($response, $page . '?sso=error&reason=' . self::REASON_PROVIDER_ERROR));
    }
  }

  /**
   * @param OidcAuthRequest|null $claimed set as soon as the request is known, for the caller's error handling
   * @throws Exception
   */
  private function finishCallback(Request $request, Response $response, ?OidcAuthRequest &$claimed): Response {
    $query = $request->getQueryParams();

    $state = $query['state'] ?? null;
    $cookie = OidcStateCookie::read($request);
    $cookieMatches = is_string($state) && $cookie !== null && hash_equals($cookie, $state);
    $authRequest = $cookieMatches ? $this->claimRequest($state) : null;
    if ($authRequest === null) {
      $origin = CorsHackMiddleware::defaultFrontendOrigin();
      $expired = $origin === null
        ? ErrorHandler::errorResponse($response, "Sign-in request expired or unknown", 400)
        : $this->redirect($response, $origin . self::LOGIN_PAGE . '?sso=error&reason=' . self::REASON_EXPIRED);
      // A cookie that belongs to another (newer) attempt is left alone, so that attempt can still finish
      return $cookieMatches ? OidcStateCookie::clear($request, $expired) : $expired;
    }

    $claimed = $authRequest;
    $returnTo = (string)$authRequest->getReturnTo();
    $isLink = $authRequest->getPurpose() === OidcAuthRequestUtils::PURPOSE_LINK;
    $failurePage = $returnTo . ($isLink ? self::SETTINGS_PAGE : self::LOGIN_PAGE);
    $fail = fn(string $reason): Response => OidcStateCookie::clear($request, $this->redirect($response, $failurePage . '?sso=error&reason=' . $reason));
    $logUserId = $isLink ? $authRequest->getUserId() : null;

    $claims = $this->verifiedClaims($query, $authRequest, $logUserId);
    if ($claims === null) {
      return $fail(self::REASON_PROVIDER_ERROR);
    }

    if ($isLink) {
      $user = Factory::getUserFactory()->get((int)$authRequest->getUserId());
      if (!$user instanceof User || $user->getIsValid() !== 1) {
        $this->log($authRequest->getUserId(), DLogEntry::WARN, "Single sign-on link refused: the user is disabled or deleted");
        return $fail(self::REASON_USER_DISABLED);
      }
      try {
        OidcIdentityUtils::link($user->getId(), $claims);
      }
      catch (OidcAlreadyLinkedException) {
        $this->log($user->getId(), DLogEntry::WARN, "Single sign-on link refused: the identity is already linked to another user");
        return $fail(self::REASON_ALREADY_LINKED);
      }
      $this->log($user->getId(), DLogEntry::INFO, "Linked a single sign-on identity");
      return OidcStateCookie::clear($request, $this->redirect($response, $returnTo . self::SETTINGS_PAGE . '?sso=linked'));
    }

    $identity = OidcIdentityUtils::find($claims->issuer, $claims->subject);
    if ($identity === null) {
      // Not linked yet: remember the verified identity so the user can link it by signing in locally
      $pending = OidcAuthRequestUtils::create(OidcAuthRequestUtils::PURPOSE_PENDING_LINK, $returnTo, null, $claims);
      return OidcStateCookie::attach($request, $this->redirect($response, $returnTo . self::LOGIN_PAGE . '?sso=link-required'), $pending['state']);
    }

    $user = Factory::getUserFactory()->get($identity->getUserId());
    if (!$user instanceof User || $user->getIsValid() !== 1) {
      $this->log($identity->getUserId(), DLogEntry::WARN, "Single sign-on login refused: the user is disabled");
      return $fail(self::REASON_USER_DISABLED);
    }

    Factory::getUserFactory()->set($user, User::LAST_LOGIN_DATE, time());
    OidcIdentityUtils::touch($identity);
    $this->log($user->getId(), DLogEntry::INFO, "Logged in via single sign-on");

    $response = OidcStateCookie::clear($request, $this->redirect($response, $returnTo . self::SSO_LANDING_PAGE));
    return $this->attachSession($request, $response, $user);
  }

  /**
   * POST link-pending {username, password}. Links the identity an unlinked SSO login left pending to
   * the local account whose password the user proves, and signs them in. Password login being switched
   * off does not apply: this is how an SSO user gets an account, and the password only proves ownership.
   *
   * @throws ResourceNotFoundError
   * @throws HttpError
   * @throws HttpForbidden
   * @throws HttpUnauthorized
   * @throws HttpConflict
   * @throws Exception
   */
  public function linkPending(Request $request, Response $response): Response {
    $this->assertEnabled();
    OidcAuthRequestUtils::purgeStale();
    CorsHackMiddleware::assertNotCrossSite($request);

    $state = OidcStateCookie::read($request);
    $pending = $state === null ? null : OidcAuthRequestUtils::peek($state, OidcAuthRequestUtils::PURPOSE_PENDING_LINK);
    if ($pending === null) {
      throw new HttpUnauthorized("No pending single sign-on link");
    }

    $body = $request->getParsedBody();
    $username = is_array($body) ? ($body['username'] ?? null) : null;
    $password = is_array($body) ? ($body['password'] ?? null) : null;
    if (!is_string($username) || $username === '' || !is_string($password) || $password === '') {
      throw new HttpError("username and password are required");
    }

    // A wrong password leaves the request usable for another try; a disabled user is a 403 from here
    $user = HashtopolisAuthenticator::verifyCredentials($username, $password);
    if ($user === null) {
      throw new HttpUnauthorized("Wrong username or password");
    }

    if (!OidcAuthRequestUtils::markUsed($pending)) {
      throw new HttpUnauthorized("No pending single sign-on link");
    }
    // markUsed scrubs the row; the object read before it still holds the identity
    $claims = new OidcClaims((string)$pending->getIssuer(), (string)$pending->getSubject(), (string)$pending->getLabel());
    try {
      $identity = OidcIdentityUtils::link($user->getId(), $claims);
    }
    catch (OidcAlreadyLinkedException) {
      $this->log($user->getId(), DLogEntry::WARN, "Single sign-on link refused: the identity is already linked to another user");
      throw new HttpConflict("This single sign-on identity is already linked to another user");
    }
    OidcIdentityUtils::touch($identity);
    $this->log($user->getId(), DLogEntry::INFO, "Linked a single sign-on identity and logged in");

    $response = OidcStateCookie::clear($request, $response->withStatus(204));
    return $this->attachSession($request, $response, $user);
  }

  /**
   * Starts a refresh token family for a user who has just signed in and sets it as the cookie.
   *
   * @throws Exception
   */
  private function attachSession(Request $request, Response $response, User $user): Response {
    return RefreshTokenCookie::attach($request, $response, RefreshTokenUtils::issue($user->getId()));
  }

  /**
   * GET identities. The signed-in user's linked identities.
   *
   * @throws HttpUnauthorized
   * @throws Exception
   */
  public function listIdentities(Request $request, Response $response): Response {
    $user = $this->currentUser($request);
    $identities = [];
    foreach (OidcIdentityUtils::listForUser($user->getId()) as $identity) {
      $identities[] = [
        'id' => $identity->getId(),
        'label' => $identity->getLabel(),
        'issuer' => $identity->getIssuer(),
        'createdAt' => $identity->getCreatedAt(),
        'lastUsedAt' => $identity->getLastUsedAt(),
      ];
    }
    return $this->json($response, ['identities' => $identities]);
  }

  /**
   * DELETE identities/{id}. Only the owner can unlink; anything else looks like a missing identity.
   *
   * @throws HttpForbidden
   * @throws HttpUnauthorized
   * @throws ResourceNotFoundError
   * @throws Exception
   */
  public function unlinkIdentity(Request $request, Response $response, int $identityId): Response {
    CorsHackMiddleware::assertNotCrossSite($request);
    $user = $this->currentUser($request);
    if (!OidcIdentityUtils::unlink($user->getId(), $identityId)) {
      throw new ResourceNotFoundError("Identity not found");
    }
    $this->log($user->getId(), DLogEntry::INFO, "Unlinked a single sign-on identity");
    return $response->withStatus(204);
  }

  /**
   * @throws ResourceNotFoundError
   */
  protected function assertEnabled(): void {
    if (!$this->config->isEnabled()) {
      throw new ResourceNotFoundError("Single sign-on is not enabled on this server");
    }
  }

  /**
   * The user the request's access token belongs to (set by JWTBeforeHandler).
   *
   * @throws HttpUnauthorized
   */
  protected function currentUser(Request $request): User {
    $userId = $request->getAttribute('userId');
    $user = is_numeric($userId) ? Factory::getUserFactory()->get((int)$userId) : null;
    if (!$user instanceof User) {
      throw new HttpUnauthorized("No signed-in user");
    }
    return $user;
  }

  /**
   * Creates a request and builds the provider URL for it. On a provider failure the request is
   * dropped, the failure logged, and null returned.
   *
   * @return array{state: string, url: string}|null
   * @throws Exception
   */
  private function startAuthorization(string $purpose, string $returnTo, ?int $userId): ?array {
    $created = OidcAuthRequestUtils::create($purpose, $returnTo, $userId);
    $authRequest = $created['request'];
    try {
      $url = $this->provider->authorizationUrl($created['state'], (string)$authRequest->getNonce(),
        OidcAuthRequestUtils::codeChallenge((string)$authRequest->getCodeVerifier()));
    }
    catch (OidcException $e) {
      Factory::getOidcAuthRequestFactory()->delete($authRequest);
      $this->log($userId, DLogEntry::WARN, "Single sign-on failed: " . $e->getMessage());
      return null;
    }
    return ['state' => $created['state'], 'url' => $url];
  }

  /**
   * Finds the login or link request for a state that matched this browser's cookie and uses it up.
   * Null when the request is unknown, expired or already used.
   */
  private function claimRequest(string $state): ?OidcAuthRequest {
    $authRequest = OidcAuthRequestUtils::peek($state, OidcAuthRequestUtils::PURPOSE_LOGIN)
      ?? OidcAuthRequestUtils::peek($state, OidcAuthRequestUtils::PURPOSE_LINK);
    if ($authRequest === null || !OidcAuthRequestUtils::markUsed($authRequest)) {
      return null;
    }
    return $authRequest;
  }

  /**
   * Exchanges the code and validates the ID token. Null (with a warning logged) on a provider error
   * response or any OidcException.
   *
   * @param array<mixed> $query
   */
  private function verifiedClaims(array $query, OidcAuthRequest $authRequest, ?int $logUserId): ?OidcClaims {
    if (isset($query['error'])) {
      $error = is_string($query['error']) && preg_match('/^[A-Za-z0-9_.-]{1,64}$/D', $query['error']) === 1 ? $query['error'] : 'unrecognised';
      $this->log($logUserId, DLogEntry::WARN, "Single sign-on failed: the provider returned error '" . $error . "'");
      return null;
    }
    $code = $query['code'] ?? null;
    if (!is_string($code) || $code === '') {
      $this->log($logUserId, DLogEntry::WARN, "Single sign-on failed: the provider's answer carried no authorization code");
      return null;
    }
    try {
      $idToken = $this->provider->exchangeCode($code, (string)$authRequest->getCodeVerifier());
      return $this->provider->validateIdToken($idToken, (string)$authRequest->getNonce());
    }
    catch (OidcException $e) {
      $this->log($logUserId, DLogEntry::WARN, "Single sign-on failed: " . $e->getMessage());
      return null;
    }
  }

  protected function log(?int $userId, string $level, string $message): void {
    if ($userId === null) {
      Util::createLogEntry(DLogEntryIssuer::API, self::LOG_ISSUER_ID, $level, $message);
      return;
    }
    Util::createLogEntry(DLogEntryIssuer::USER, (string)$userId, $level, $message);
  }

  protected function redirect(Response $response, string $location): Response {
    return $response->withStatus(302)->withHeader('Location', $location);
  }

  /**
   * @param array<string, mixed> $data
   */
  protected function json(Response $response, array $data): Response {
    $response->getBody()->write((string)json_encode($data, JSON_UNESCAPED_SLASHES));
    return $response->withHeader('Content-Type', 'application/json');
  }
}
