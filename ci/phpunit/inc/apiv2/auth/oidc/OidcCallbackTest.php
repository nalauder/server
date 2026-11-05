<?php

namespace Hashtopolis\inc\apiv2\auth\oidc;

use Hashtopolis\dba\Factory;
use Hashtopolis\dba\models\OidcIdentity;
use Hashtopolis\dba\models\User;
use Hashtopolis\inc\apiv2\auth\HashtopolisAuthenticator;
use Hashtopolis\inc\apiv2\error\HttpForbidden;
use Hashtopolis\inc\apiv2\helper\ResetUserPasswordHelperAPI;
use Hashtopolis\inc\Encryption;
use Hashtopolis\inc\utils\OidcIdentityUtils;
use Psr\Container\ContainerInterface;
use Hashtopolis\dba\models\LogEntry;
use Hashtopolis\dba\models\OidcAuthRequest;
use Hashtopolis\dba\OrderFilter;
use Hashtopolis\dba\QueryFilter;
use Hashtopolis\inc\defines\DLogEntry;
use Hashtopolis\inc\utils\OidcAuthRequestUtils;
use Hashtopolis\TestBase;
use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;

require_once(dirname(__FILE__) . '/../../../../TestBase.php');
require_once(dirname(__FILE__) . '/../../../../../../src/inc/startup/include.php');

/**
 * Serves the discovery document, then fails like an unreachable token endpoint would: with a
 * transport error whose message must never reach the browser or the log.
 */
final class UnreachableTokenEndpointClient implements OidcHttpClient {
  public bool $failDiscovery = false;

  public function __construct(private readonly string $issuer) {
  }

  public function getJson(string $url): array {
    if ($this->failDiscovery) {
      throw new RuntimeException("connect to idp.example.test timed out");
    }
    return [
      'issuer' => $this->issuer,
      'authorization_endpoint' => $this->issuer . '/auth',
      'token_endpoint' => $this->issuer . '/token',
      'jwks_uri' => $this->issuer . '/certs',
    ];
  }

  public function postForm(string $url, array $fields): array {
    throw new RuntimeException("connect failed while sending code " . ($fields['code'] ?? ''));
  }
}

final class OidcCallbackTest extends TestBase {
  private const ISSUER = 'https://idp.example.test/realms/test';
  private const RETURN_TO = 'http://localhost:4200';
  private const CODE = 'authorization-code-that-must-not-be-logged';

  private OidcController $controller;
  private OidcConfig $config;
  private UnreachableTokenEndpointClient $http;
  private string $cacheDir;
  private int $lastLogId;
  /** @var OidcAuthRequest[] */
  private array $requests = [];

  #[Override]
  protected function setUp(): void {
    parent::setUp();
    $config = $this->config = $this->makeConfig();
    $this->cacheDir = sys_get_temp_dir() . '/oidc-callback-test-' . bin2hex(random_bytes(6));
    mkdir($this->cacheDir, 0700);
    $this->http = new UnreachableTokenEndpointClient(self::ISSUER);
    $this->controller = new OidcController($config, new OidcProvider($config, $this->http, $this->cacheDir));
    $this->lastLogId = $this->latestLogId();
  }

  /**
   * @param array<string, string> $extra
   */
  private function makeConfig(array $extra = []): OidcConfig {
    return new OidcConfig(array_merge([
      'HASHTOPOLIS_OIDC_ISSUER' => self::ISSUER,
      'HASHTOPOLIS_OIDC_CLIENT_ID' => 'hashtopolis',
      'HASHTOPOLIS_OIDC_CLIENT_SECRET' => 'test-client-secret',
      'HASHTOPOLIS_BACKEND_URL' => 'http://localhost/api/v2',
    ], $extra));
  }

  #[Override]
  protected function tearDown(): void {
    OidcConfig::setInstance(null);
    foreach ($this->requests as $request) {
      Factory::getOidcAuthRequestFactory()->massDeletion([
        Factory::FILTER => new QueryFilter(OidcAuthRequest::OIDC_AUTH_REQUEST_ID, $request->getId(), "=")
      ]);
    }
    Factory::getLogEntryFactory()->massDeletion([
      Factory::FILTER => new QueryFilter(LogEntry::LOG_ENTRY_ID, $this->lastLogId, ">")
    ]);
    array_map('unlink', glob($this->cacheDir . '/*') ?: []);
    @rmdir($this->cacheDir);
    parent::tearDown();
  }

  private function latestLogId(): int {
    $entry = Factory::getLogEntryFactory()->filter([
      Factory::ORDER => new OrderFilter(LogEntry::LOG_ENTRY_ID, "DESC LIMIT 1")
    ], true);
    return $entry instanceof LogEntry ? $entry->getId() : 0;
  }

  /**
   * @return LogEntry[] entries written since setUp
   */
  private function newLogEntries(): array {
    return Factory::getLogEntryFactory()->filter([
      Factory::FILTER => new QueryFilter(LogEntry::LOG_ENTRY_ID, $this->lastLogId, ">")
    ]);
  }

  private function startRequest(string $purpose, ?int $userId = null): string {
    $made = OidcAuthRequestUtils::create($purpose, self::RETURN_TO, $userId);
    $this->requests[] = $made['request'];
    return $made['state'];
  }

  /**
   * @param array<string, string> $query
   */
  private function runCallback(array $query, ?string $cookie): ResponseInterface {
    $request = (new ServerRequestFactory())
      ->createServerRequest('GET', 'http://localhost/api/v2/auth/oidc/callback?' . http_build_query($query))
      ->withQueryParams($query);
    if ($cookie !== null) {
      $request = $request->withCookieParams([OidcStateCookie::COOKIE_NAME => $cookie]);
    }
    return $this->controller->callback($request, (new ResponseFactory())->createResponse());
  }

  private function assertProviderErrorLogged(): void {
    $entries = $this->newLogEntries();
    $this->assertCount(1, $entries);
    $this->assertSame(DLogEntry::WARN, $entries[0]->getLevel());
    $this->assertStringContainsString('OIDC provider error (RuntimeException)', $entries[0]->getMessage());
    $this->assertStringNotContainsString(self::CODE, $entries[0]->getMessage());
  }

  public function testProviderFailureRedirectsWithProviderError(): void {
    $state = $this->startRequest(OidcAuthRequestUtils::PURPOSE_LOGIN);

    $response = $this->runCallback(['code' => self::CODE, 'state' => $state], $state);

    $this->assertSame(302, $response->getStatusCode());
    $this->assertSame(self::RETURN_TO . '/auth?sso=error&reason=provider_error', $response->getHeaderLine('Location'));
    $this->assertStringStartsWith('oidcState=; ', $response->getHeaderLine('Set-Cookie'));
    $this->assertStringNotContainsString('refreshToken', $response->getHeaderLine('Set-Cookie'));
    $this->assertProviderErrorLogged();
    $this->assertNull(OidcAuthRequestUtils::peek($state, OidcAuthRequestUtils::PURPOSE_LOGIN), 'the request is used up');
  }

  public function testLinkProviderFailureRedirectsToSettings(): void {
    $state = $this->startRequest(OidcAuthRequestUtils::PURPOSE_LINK, 1);

    $response = $this->runCallback(['code' => self::CODE, 'state' => $state], $state);

    $this->assertSame(self::RETURN_TO . '/account/acc-settings?sso=error&reason=provider_error', $response->getHeaderLine('Location'));
    $this->assertProviderErrorLogged();
  }

  public function testMismatchedCookieIsExpired(): void {
    $state = $this->startRequest(OidcAuthRequestUtils::PURPOSE_LOGIN);
    $other = $this->startRequest(OidcAuthRequestUtils::PURPOSE_LOGIN);

    $response = $this->runCallback(['code' => self::CODE, 'state' => $state], $other);

    $this->assertSame(302, $response->getStatusCode());
    $this->assertStringEndsWith('/auth?sso=error&reason=expired', $response->getHeaderLine('Location'));
    $this->assertSame('', $response->getHeaderLine('Set-Cookie'), 'the cookie of the other attempt is left alone');
    $this->assertNotNull(OidcAuthRequestUtils::peek($state, OidcAuthRequestUtils::PURPOSE_LOGIN), 'a mismatch does not use up the request');
  }

  public function testMissingCookieIsExpiredWithoutClearing(): void {
    $state = $this->startRequest(OidcAuthRequestUtils::PURPOSE_LOGIN);

    $response = $this->runCallback(['code' => self::CODE, 'state' => $state], null);

    $this->assertStringEndsWith('/auth?sso=error&reason=expired', $response->getHeaderLine('Location'));
    $this->assertSame('', $response->getHeaderLine('Set-Cookie'));
  }

  public function testUsedRequestIsExpiredAndClearsMatchingCookie(): void {
    $state = $this->startRequest(OidcAuthRequestUtils::PURPOSE_LOGIN);
    $this->assertNotNull(OidcAuthRequestUtils::consume($state, OidcAuthRequestUtils::PURPOSE_LOGIN));

    $response = $this->runCallback(['code' => self::CODE, 'state' => $state], $state);

    $this->assertStringEndsWith('/auth?sso=error&reason=expired', $response->getHeaderLine('Location'));
    $this->assertStringStartsWith('oidcState=; ', $response->getHeaderLine('Set-Cookie'));
    $this->assertCount(0, $this->newLogEntries(), 'the provider is not contacted for a used request');
  }

  public function testLoginProviderFailureRedirectsWithProviderError(): void {
    $this->http->failDiscovery = true;
    $request = (new ServerRequestFactory())
      ->createServerRequest('GET', 'http://localhost/api/v2/auth/oidc/login')
      ->withQueryParams(['returnTo' => self::RETURN_TO]);

    $response = $this->controller->login($request, (new ResponseFactory())->createResponse());

    $this->assertSame(302, $response->getStatusCode());
    $this->assertSame(self::RETURN_TO . '/auth?sso=error&reason=provider_error', $response->getHeaderLine('Location'));
    $this->assertStringNotContainsString('oidcState=', $response->getHeaderLine('Set-Cookie'));
    $entries = $this->newLogEntries();
    $this->assertCount(1, $entries);
    $this->assertSame(DLogEntry::WARN, $entries[0]->getLevel());
  }

  public function testUnexpectedFaultRedirectsWithProviderError(): void {
    $provider = $this->createStub(OidcProvider::class);
    $provider->method('exchangeCode')->willThrowException(new \TypeError('database said secret-detail'));
    $controller = new OidcController($this->config, $provider);
    $state = $this->startRequest(OidcAuthRequestUtils::PURPOSE_LOGIN);
    $request = (new ServerRequestFactory())
      ->createServerRequest('GET', 'http://localhost/api/v2/auth/oidc/callback')
      ->withQueryParams(['code' => self::CODE, 'state' => $state])
      ->withCookieParams([OidcStateCookie::COOKIE_NAME => $state]);

    $response = $controller->callback($request, (new ResponseFactory())->createResponse());

    $this->assertSame(302, $response->getStatusCode());
    $this->assertSame(self::RETURN_TO . '/auth?sso=error&reason=provider_error', $response->getHeaderLine('Location'));
    $this->assertStringStartsWith('oidcState=; ', $response->getHeaderLine('Set-Cookie'));
    $entries = $this->newLogEntries();
    $this->assertCount(1, $entries);
    $this->assertSame(DLogEntry::WARN, $entries[0]->getLevel());
    $this->assertStringContainsString('TypeError', $entries[0]->getMessage());
    $this->assertStringNotContainsString('secret-detail', $entries[0]->getMessage());
  }

  public function testCallbackPurgesStaleRequests(): void {
    $state = $this->startRequest(OidcAuthRequestUtils::PURPOSE_LOGIN);
    $this->assertNotNull(OidcAuthRequestUtils::consume($state, OidcAuthRequestUtils::PURPOSE_LOGIN));
    $usedId = $this->requests[0]->getId();

    $this->runCallback(['state' => 'unrelated'], null);

    $this->assertNull(Factory::getOidcAuthRequestFactory()->get($usedId), 'the used row is gone');
  }

  public function testLinkRefusedWhenUserDisabledIsLogged(): void {
    $user = $this->createUser('oidc_disabled');
    Factory::getUserFactory()->set($user, User::IS_VALID, 0);
    $state = $this->startRequest(OidcAuthRequestUtils::PURPOSE_LINK, $user->getId());
    $claims = new OidcClaims(self::ISSUER, 'sub-disabled', 'bob');
    $provider = $this->createStub(OidcProvider::class);
    $provider->method('exchangeCode')->willReturn('id-token');
    $provider->method('validateIdToken')->willReturn($claims);
    $controller = new OidcController($this->config, $provider);
    $request = (new ServerRequestFactory())
      ->createServerRequest('GET', 'http://localhost/api/v2/auth/oidc/callback')
      ->withQueryParams(['code' => self::CODE, 'state' => $state])
      ->withCookieParams([OidcStateCookie::COOKIE_NAME => $state]);

    $response = $controller->callback($request, (new ResponseFactory())->createResponse());

    $this->assertSame(self::RETURN_TO . '/account/acc-settings?sso=error&reason=user_disabled', $response->getHeaderLine('Location'));
    $entries = array_values(array_filter($this->newLogEntries(), fn(LogEntry $e) => $e->getLevel() === DLogEntry::WARN));
    $this->assertCount(1, $entries);
    $this->assertSame((string)$user->getId(), (string)$entries[0]->getIssuerId());
    $this->assertNull(OidcIdentityUtils::find(self::ISSUER, 'sub-disabled'));
  }

  private function localLoginOff(): OidcConfig {
    $config = $this->makeConfig(['HASHTOPOLIS_LOCAL_LOGIN_ENABLED' => 'false']);
    OidcConfig::setInstance($config);
    return $config;
  }

  public function testTokenEndpointForbiddenWhenLocalLoginDisabled(): void {
    $this->localLoginOff();

    $this->expectException(HttpForbidden::class);
    (new HashtopolisAuthenticator())(['user' => 'admin', 'password' => 'whatever']);
  }

  public function testResetPasswordForbiddenWhenLocalLoginDisabled(): void {
    $this->localLoginOff();
    $api = new ResetUserPasswordHelperAPI($this->createStub(ContainerInterface::class));

    $this->expectException(HttpForbidden::class);
    $api->actionPost([User::USERNAME => 'admin', User::EMAIL => 'admin@example.test']);
  }

  public function testLinkPendingAllowedWhenLocalLoginDisabled(): void {
    $config = $this->localLoginOff();
    $this->assertFalse($config->isLocalLoginEnabled());
    $user = $this->createUser('oidc_pending');
    $password = 'pending-link-pass-1';
    Factory::getUserFactory()->set($user, User::PASSWORD_HASH, Encryption::passwordHash($password, $user->getPasswordSalt()));
    $made = OidcAuthRequestUtils::create(OidcAuthRequestUtils::PURPOSE_PENDING_LINK, self::RETURN_TO, null,
      new OidcClaims(self::ISSUER, 'sub-pending', 'bob'));
    $this->requests[] = $made['request'];
    $controller = new OidcController($config, new OidcProvider($config, $this->http, $this->cacheDir));
    $request = (new ServerRequestFactory())
      ->createServerRequest('POST', 'http://localhost/api/v2/auth/oidc/link-pending')
      ->withParsedBody(['username' => $user->getUsername(), 'password' => $password])
      ->withCookieParams([OidcStateCookie::COOKIE_NAME => $made['state']]);

    try {
      $response = $controller->linkPending($request, (new ResponseFactory())->createResponse());

      $this->assertSame(204, $response->getStatusCode());
      $cookies = implode("\n", $response->getHeader('Set-Cookie'));
      $this->assertStringContainsString('refreshToken=', $cookies);
      $this->assertStringContainsString('oidcState=; ', $cookies);
      $identity = OidcIdentityUtils::find(self::ISSUER, 'sub-pending');
      $this->assertInstanceOf(OidcIdentity::class, $identity);
      $this->assertSame($user->getId(), $identity->getUserId());
      $this->assertNotNull($identity->getLastUsedAt());
      $this->assertNull(OidcAuthRequestUtils::peek($made['state'], OidcAuthRequestUtils::PURPOSE_PENDING_LINK), 'the request is used up');
    }
    finally {
      Factory::getOidcIdentityFactory()->massDeletion([
        Factory::FILTER => new QueryFilter(OidcIdentity::USER_ID, $user->getId(), "=")
      ]);
    }
  }
}
