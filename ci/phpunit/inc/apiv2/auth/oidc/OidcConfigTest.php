<?php

namespace Hashtopolis\inc\apiv2\auth\oidc;

use Hashtopolis\inc\apiv2\error\HttpForbidden;
use PHPUnit\Framework\TestCase;

require_once(dirname(__FILE__) . '/../../../../../../src/inc/startup/include.php');

final class OidcConfigTest extends TestCase {
  protected function tearDown(): void {
    OidcConfig::setInstance(null);
  }

  /**
   * @param array<string, string> $extra
   * @return array<string, string>
   */
  private function full(array $extra = []): array {
    return array_merge([
      'HASHTOPOLIS_OIDC_ISSUER' => 'https://idp.example.test/realms/x/',
      'HASHTOPOLIS_OIDC_CLIENT_ID' => 'hashtopolis',
      'HASHTOPOLIS_OIDC_CLIENT_SECRET' => 'secret',
    ], $extra);
  }

  public function testDisabledWhenIssuerUnset(): void {
    $this->assertFalse((new OidcConfig([]))->isEnabled());
  }

  public function testDisabledWhenSecretMissing(): void {
    $s = $this->full();
    unset($s['HASHTOPOLIS_OIDC_CLIENT_SECRET']);
    $this->assertFalse((new OidcConfig($s))->isEnabled());
  }

  public function testEnabledWithAllThree(): void {
    $c = new OidcConfig($this->full());
    $this->assertTrue($c->isEnabled());
    $this->assertSame('https://idp.example.test/realms/x', $c->getIssuer());
    $this->assertSame('hashtopolis', $c->getClientId());
    $this->assertSame('secret', $c->getClientSecret());
  }

  public function testEmptyStringCountsAsUnset(): void {
    $this->assertFalse((new OidcConfig($this->full(['HASHTOPOLIS_OIDC_CLIENT_SECRET' => ''])))->isEnabled());
    $this->assertFalse((new OidcConfig(['HASHTOPOLIS_OIDC_ISSUER' => '']))->isEnabled());
  }

  public function testDefaults(): void {
    $c = new OidcConfig($this->full());
    $this->assertSame('openid profile email', $c->getScopes());
    $this->assertSame('SSO', $c->getDisplayName());
    $this->assertFalse($c->allowsInsecureHttp());
  }

  public function testRedirectUriFromBackendUrl(): void {
    $c = new OidcConfig(['HASHTOPOLIS_BACKEND_URL' => 'http://localhost:8080/api/v2/']);
    $this->assertSame('http://localhost:8080/api/v2/auth/oidc/callback', $c->getRedirectUri());
  }

  public function testLocalLoginCannotBeDisabledWithoutSso(): void {
    $c = new OidcConfig(['HASHTOPOLIS_LOCAL_LOGIN_ENABLED' => 'false']);
    $this->assertTrue($c->isLocalLoginEnabled());
  }

  public function testLocalLoginDisabled(): void {
    $this->assertFalse((new OidcConfig($this->full(['HASHTOPOLIS_LOCAL_LOGIN_ENABLED' => 'false'])))->isLocalLoginEnabled());
    $this->assertFalse((new OidcConfig($this->full(['HASHTOPOLIS_LOCAL_LOGIN_ENABLED' => '0'])))->isLocalLoginEnabled());
    $this->assertTrue((new OidcConfig($this->full()))->isLocalLoginEnabled());
  }

  public function testAssertLocalLoginAllowedThrowsHttpForbidden(): void {
    $c = new OidcConfig($this->full(['HASHTOPOLIS_LOCAL_LOGIN_ENABLED' => 'false']));
    $this->expectException(HttpForbidden::class);
    $this->expectExceptionMessage('Password login is disabled on this server. Use single sign-on.');
    $c->assertLocalLoginAllowed();
  }

  public function testAssertLocalLoginAllowedPassesWhenEnabled(): void {
    (new OidcConfig($this->full()))->assertLocalLoginAllowed();
    $this->addToAssertionCount(1);
  }

  public function testRepeatedCallsKeepReturnValues(): void {
    $c = new OidcConfig(['HASHTOPOLIS_OIDC_ISSUER' => 'https://idp.example.test', 'HASHTOPOLIS_LOCAL_LOGIN_ENABLED' => 'false']);
    for ($i = 0; $i < 3; $i++) {
      $this->assertFalse($c->isEnabled());
      $this->assertTrue($c->isLocalLoginEnabled());
    }
  }
}
