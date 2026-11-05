<?php

namespace Hashtopolis\inc\utils;

use Exception;
use Hashtopolis\dba\Factory;
use Hashtopolis\dba\models\OidcAuthRequest;
use Hashtopolis\dba\models\OidcIdentity;
use Hashtopolis\dba\QueryFilter;
use Hashtopolis\dba\UpdateSet;
use Hashtopolis\inc\apiv2\auth\oidc\OidcClaims;
use Hashtopolis\TestBase;

require_once(dirname(__FILE__) . '/../../TestBase.php');
require_once(dirname(__FILE__) . '/../../../../src/inc/startup/include.php');

final class OidcAuthRequestUtilsTest extends TestBase {
  /** @var OidcAuthRequest[] */
  private array $created = [];
  
  protected function tearDown(): void {
    foreach ($this->created as $request) {
      Factory::getOidcAuthRequestFactory()->massDeletion([
        Factory::FILTER => new QueryFilter(OidcAuthRequest::OIDC_AUTH_REQUEST_ID, $request->getId(), "=")
      ]);
    }
    parent::tearDown();
  }
  
  /**
   * @return array{state: string, request: OidcAuthRequest}
   * @throws Exception
   */
  private function make(string $purpose = OidcAuthRequestUtils::PURPOSE_LOGIN, ?OidcClaims $pending = null): array {
    $result = OidcAuthRequestUtils::create($purpose, 'https://ui.example.test', null, $pending);
    $this->created[] = $result['request'];
    return $result;
  }
  
  /**
   * @throws Exception
   */
  private function expire(OidcAuthRequest $request): void {
    Factory::getOidcAuthRequestFactory()->massUpdate([
      Factory::FILTER => new QueryFilter(OidcAuthRequest::OIDC_AUTH_REQUEST_ID, $request->getId(), "="),
      Factory::UPDATE => [new UpdateSet(OidcAuthRequest::EXPIRES_AT, time() - 1)]
    ]);
  }
  
  public function testCreateStoresOnlyHash(): void {
    $made = $this->make();
    $state = $made['state'];
    $this->assertSame(64, strlen($state));
    
    foreach (Factory::getOidcAuthRequestFactory()->filter([]) as $row) {
      foreach ($row->getKeyValueDict() as $value) {
        $this->assertNotSame($state, $value);
      }
    }
    $this->assertNotNull(OidcAuthRequestUtils::peek($state, OidcAuthRequestUtils::PURPOSE_LOGIN));
    $this->assertSame(32, strlen($made['request']->getNonce()));
    $this->assertNotEmpty($made['request']->getCodeVerifier());
  }
  
  public function testPendingLinkCarriesClaimsAndNoVerifier(): void {
    $made = $this->make(OidcAuthRequestUtils::PURPOSE_PENDING_LINK, new OidcClaims('https://idp.example.test', 'sub-1', 'alice'));
    $request = $made['request'];
    $this->assertNull($request->getCodeVerifier());
    $this->assertSame('https://idp.example.test', $request->getIssuer());
    $this->assertSame('sub-1', $request->getSubject());
    $this->assertSame('alice', $request->getLabel());
  }
  
  public function testConsumeOnce(): void {
    $state = $this->make()['state'];
    $this->assertNotNull(OidcAuthRequestUtils::consume($state, OidcAuthRequestUtils::PURPOSE_LOGIN));
    $this->assertNull(OidcAuthRequestUtils::consume($state, OidcAuthRequestUtils::PURPOSE_LOGIN));
  }
  
  public function testMarkUsedHasOneWinner(): void {
    $request = $this->make()['request'];
    $this->assertTrue(OidcAuthRequestUtils::markUsed($request));
    $this->assertFalse(OidcAuthRequestUtils::markUsed($request));
  }
  
  public function testConsumeWrongPurposeReturnsNull(): void {
    $state = $this->make()['state'];
    $this->assertNull(OidcAuthRequestUtils::consume($state, OidcAuthRequestUtils::PURPOSE_LINK));
    $this->assertNotNull(OidcAuthRequestUtils::peek($state, OidcAuthRequestUtils::PURPOSE_LOGIN));
  }
  
  public function testConsumeUnknownStateReturnsNull(): void {
    $this->assertNull(OidcAuthRequestUtils::consume('nope', OidcAuthRequestUtils::PURPOSE_LOGIN));
  }
  
  public function testConsumeExpiredReturnsNull(): void {
    $made = $this->make();
    $this->expire($made['request']);
    $this->assertNull(OidcAuthRequestUtils::consume($made['state'], OidcAuthRequestUtils::PURPOSE_LOGIN));
  }
  
  public function testPeekDoesNotConsume(): void {
    $state = $this->make()['state'];
    $this->assertNotNull(OidcAuthRequestUtils::peek($state, OidcAuthRequestUtils::PURPOSE_LOGIN));
    $this->assertNotNull(OidcAuthRequestUtils::peek($state, OidcAuthRequestUtils::PURPOSE_LOGIN));
    $this->assertNotNull(OidcAuthRequestUtils::consume($state, OidcAuthRequestUtils::PURPOSE_LOGIN));
    $this->assertNull(OidcAuthRequestUtils::peek($state, OidcAuthRequestUtils::PURPOSE_LOGIN));
  }
  
  public function testCreateDeletesExpiredRows(): void {
    $old = $this->make();
    $this->expire($old['request']);
    $this->make();
    
    $qF = new QueryFilter(OidcAuthRequest::OIDC_AUTH_REQUEST_ID, $old['request']->getId(), "=");
    $this->assertNull(Factory::getOidcAuthRequestFactory()->filter([Factory::FILTER => $qF], true));
  }
  
  public function testCodeChallengeRfc7636Vector(): void {
    $this->assertSame(
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      OidcAuthRequestUtils::codeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
    );
  }
  
  public function testSubjectsDifferingInCaseStayDistinct(): void {
    $issuer = 'https://idp.example.test';
    $a = $this->make(OidcAuthRequestUtils::PURPOSE_PENDING_LINK, new OidcClaims($issuer, 'CaseSub', 'x'))['request'];
    $b = $this->make(OidcAuthRequestUtils::PURPOSE_PENDING_LINK, new OidcClaims($issuer, 'casesub', 'x'))['request'];
    $this->assertSame('CaseSub', $a->getSubject());
    $this->assertSame('casesub', $b->getSubject());
    
    // the unique key on (issuer, subject) must not treat them as equal
    $user = $this->createUser('oidc_case');
    $now = time();
    $factory = Factory::getOidcIdentityFactory();
    $first = $factory->save(new OidcIdentity(null, $user->getId(), $issuer, 'CaseSub', 'x', $now, null));
    $second = $factory->save(new OidcIdentity(null, $user->getId(), $issuer, 'casesub', 'x', $now, null));
    $this->assertInstanceOf(OidcIdentity::class, $first);
    $this->assertInstanceOf(OidcIdentity::class, $second);
    $this->assertNotSame($first->getId(), $second->getId());
  }
}
