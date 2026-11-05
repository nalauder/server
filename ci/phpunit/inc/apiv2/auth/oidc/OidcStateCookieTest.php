<?php

namespace Hashtopolis\inc\apiv2\auth\oidc;

use Hashtopolis\inc\apiv2\auth\RefreshTokenCookie;
use Hashtopolis\inc\StartupConfig;
use Override;
use PHPUnit\Framework\TestCase;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;

final class OidcStateCookieTest extends TestCase {
  private const VARS = ["HASHTOPOLIS_REFRESH_COOKIE_SAMESITE", "HASHTOPOLIS_REFRESH_COOKIE_SECURE"];
  private const STATE = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  
  #[Override]
  protected function setUp(): void {
    parent::setUp();
    $this->resetEnv();
  }
  
  #[Override]
  protected function tearDown(): void {
    $this->resetEnv();
    parent::tearDown();
  }
  
  private function resetEnv(): void {
    foreach (self::VARS as $name) {
      putenv($name);
    }
    StartupConfig::reload();
  }
  
  private function setSameSite(string $value): void {
    putenv("HASHTOPOLIS_REFRESH_COOKIE_SAMESITE=" . $value);
    StartupConfig::reload();
  }
  
  private function request(string $uri = "http://hashtopolis.example.test/api/v2/auth/oidc/login"): \Psr\Http\Message\ServerRequestInterface {
    return (new ServerRequestFactory())->createServerRequest("GET", $uri);
  }
  
  private function attached(?string $uri = null): string {
    $response = OidcStateCookie::attach($uri === null ? $this->request() : $this->request($uri), (new ResponseFactory())->createResponse(), self::STATE);
    return $response->getHeaderLine("Set-Cookie");
  }
  
  public function testStateCookieAttributesLax(): void {
    $header = $this->attached();
    
    $this->assertStringStartsWith("oidcState=" . self::STATE . "; Path=/api/v2/auth/oidc; Max-Age=600; Expires=", $header);
    $this->assertStringContainsString("; HttpOnly", $header);
    $this->assertStringContainsString("; SameSite=Lax", $header);
    $this->assertStringNotContainsString("Secure", $header);
  }
  
  public function testSecureFollowsRequestScheme(): void {
    $this->assertStringContainsString("; Secure", $this->attached("https://hashtopolis.example.test/api/v2/auth/oidc/login"));
  }
  
  public function testStateCookieSameSiteNoneFollowsRefreshSetting(): void {
    $this->setSameSite("None");
    $header = $this->attached();
    
    $this->assertStringContainsString("; SameSite=None", $header);
    $this->assertStringEndsWith("; Secure", $header);
  }
  
  public function testStateCookieNeverStrict(): void {
    $this->setSameSite("Strict");
    $this->assertStringContainsString("; SameSite=Lax", $this->attached());
    $this->assertStringNotContainsString("Strict", $this->attached());
  }
  
  public function testClearExpiresCookie(): void {
    $response = OidcStateCookie::clear($this->request(), (new ResponseFactory())->createResponse());
    $header = $response->getHeaderLine("Set-Cookie");
    
    $this->assertStringStartsWith("oidcState=; Path=/api/v2/auth/oidc; Max-Age=0;", $header);
    $this->assertStringContainsString("; HttpOnly", $header);
  }
  
  public function testReadAcceptsOnlyWellFormedState(): void {
    $with = fn($v) => $this->request()->withCookieParams(["oidcState" => $v]);
    
    $this->assertSame(self::STATE, OidcStateCookie::read($with(self::STATE)));
    $this->assertNull(OidcStateCookie::read($this->request()));
    $this->assertNull(OidcStateCookie::read($with("")));
    $this->assertNull(OidcStateCookie::read($with(strtoupper(self::STATE))));
    $this->assertNull(OidcStateCookie::read($with(substr(self::STATE, 1))));
    $this->assertNull(OidcStateCookie::read($with(self::STATE . "0")));
    $this->assertNull(OidcStateCookie::read($with(self::STATE . "\n")));
    $this->assertNull(OidcStateCookie::read($this->request()->withCookieParams(["oidcState" => [self::STATE]])));
  }
  
  public function testRefreshTokenCookieOutputUnchanged(): void {
    $this->setSameSite("None");
    $response = RefreshTokenCookie::clear($this->request(), (new ResponseFactory())->createResponse());
    
    $this->assertMatchesRegularExpression(
      '/^refreshToken=; Path=\/api\/v2\/auth\/refresh; Max-Age=0; Expires=[^;]+; HttpOnly; SameSite=None; Secure$/',
      $response->getHeaderLine("Set-Cookie")
    );
    
    $this->setSameSite("Strict");
    $response = RefreshTokenCookie::clear($this->request(), (new ResponseFactory())->createResponse());
    $this->assertMatchesRegularExpression(
      '/^refreshToken=; Path=\/api\/v2\/auth\/refresh; Max-Age=0; Expires=[^;]+; HttpOnly; SameSite=Strict$/',
      $response->getHeaderLine("Set-Cookie")
    );
  }
}
