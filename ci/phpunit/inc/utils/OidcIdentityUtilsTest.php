<?php

namespace Hashtopolis\inc\utils;

use Exception;
use Hashtopolis\dba\Factory;
use Hashtopolis\dba\models\OidcIdentity;
use Hashtopolis\dba\QueryFilter;
use Hashtopolis\inc\apiv2\auth\oidc\OidcAlreadyLinkedException;
use Hashtopolis\inc\apiv2\auth\oidc\OidcClaims;
use Hashtopolis\TestBase;
use PDOException;

require_once(dirname(__FILE__) . '/../../TestBase.php');
require_once(dirname(__FILE__) . '/../../../../src/inc/startup/include.php');

final class OidcIdentityUtilsTest extends TestBase {
  private const ISSUER = 'https://idp.example.test';
  
  /** @var OidcIdentity[] */
  private array $created = [];
  
  protected function tearDown(): void {
    foreach ($this->created as $identity) {
      Factory::getOidcIdentityFactory()->massDeletion([
        Factory::FILTER => new QueryFilter(OidcIdentity::OIDC_IDENTITY_ID, $identity->getId(), "=")
      ]);
    }
    parent::tearDown();
  }
  
  /**
   * @throws Exception
   */
  private function link(int $userId, OidcClaims $claims): OidcIdentity {
    $identity = OidcIdentityUtils::link($userId, $claims);
    $this->created[] = $identity;
    return $identity;
  }
  
  /**
   * @throws Exception
   */
  public function testLinkAndFind(): void {
    $user = $this->createUser('oidc_link');
    $subject = 'sub-' . uniqid();
    $before = time();
    $identity = $this->link($user->getId(), new OidcClaims(self::ISSUER, $subject, 'alice@example.test'));
    
    $this->assertNotNull($identity->getId());
    $this->assertGreaterThanOrEqual($before, $identity->getCreatedAt());
    $this->assertNull($identity->getLastUsedAt());
    
    $found = OidcIdentityUtils::find(self::ISSUER, $subject);
    $this->assertNotNull($found);
    $this->assertSame($identity->getId(), $found->getId());
    $this->assertSame($user->getId(), $found->getUserId());
    $this->assertSame('alice@example.test', $found->getLabel());
    
    $this->assertNull(OidcIdentityUtils::find(self::ISSUER, strtoupper($subject)));
    $this->assertNull(OidcIdentityUtils::find(self::ISSUER . '/', $subject));
  }
  
  /**
   * @throws Exception
   */
  public function testLinkSameUserIsIdempotent(): void {
    $user = $this->createUser('oidc_idem');
    $claims = new OidcClaims(self::ISSUER, 'sub-' . uniqid(), 'alice');
    $first = $this->link($user->getId(), $claims);
    $second = OidcIdentityUtils::link($user->getId(), new OidcClaims($claims->issuer, $claims->subject, 'renamed'));
    
    $this->assertSame($first->getId(), $second->getId());
    $this->assertSame('alice', $second->getLabel());
    $this->assertCount(1, OidcIdentityUtils::listForUser($user->getId()));
  }
  
  /**
   * @throws Exception
   */
  public function testLinkOtherUserThrows(): void {
    $alice = $this->createUser('oidc_a');
    $bob = $this->createUser('oidc_b');
    $claims = new OidcClaims(self::ISSUER, 'sub-' . uniqid(), 'alice');
    $identity = $this->link($alice->getId(), $claims);
    
    try {
      OidcIdentityUtils::link($bob->getId(), $claims);
      $this->fail('Expected OidcAlreadyLinkedException');
    }
    catch (OidcAlreadyLinkedException) {
      $this->assertSame($alice->getId(), OidcIdentityUtils::find($claims->issuer, $claims->subject)->getUserId());
      $this->assertSame([], OidcIdentityUtils::listForUser($bob->getId()));
      $this->assertSame($identity->getId(), OidcIdentityUtils::find($claims->issuer, $claims->subject)->getId());
    }
  }
  
  /**
   * @throws Exception
   */
  public function testSameSubjectDifferentIssuerIsDistinct(): void {
    $alice = $this->createUser('oidc_a');
    $bob = $this->createUser('oidc_b');
    $subject = 'sub-' . uniqid();
    $one = $this->link($alice->getId(), new OidcClaims('https://one.example.test', $subject, 'alice'));
    $two = $this->link($bob->getId(), new OidcClaims('https://two.example.test', $subject, 'bob'));
    
    $this->assertNotSame($one->getId(), $two->getId());
    $this->assertSame($alice->getId(), OidcIdentityUtils::find('https://one.example.test', $subject)->getUserId());
    $this->assertSame($bob->getId(), OidcIdentityUtils::find('https://two.example.test', $subject)->getUserId());
  }
  
  /**
   * @throws Exception
   */
  public function testUnlinkOwnOnly(): void {
    $alice = $this->createUser('oidc_a');
    $bob = $this->createUser('oidc_b');
    $claims = new OidcClaims(self::ISSUER, 'sub-' . uniqid(), 'alice');
    $identity = $this->link($alice->getId(), $claims);
    
    $this->assertFalse(OidcIdentityUtils::unlink($bob->getId(), $identity->getId()));
    $this->assertNotNull(OidcIdentityUtils::find($claims->issuer, $claims->subject));
    $this->assertFalse(OidcIdentityUtils::unlink($alice->getId(), $identity->getId() + 100000));
    
    $this->assertTrue(OidcIdentityUtils::unlink($alice->getId(), $identity->getId()));
    $this->assertNull(OidcIdentityUtils::find($claims->issuer, $claims->subject));
  }
  
  /**
   * @throws Exception
   */
  public function testListForUserOrderedByCreatedAt(): void {
    $user = $this->createUser('oidc_list');
    $newer = $this->link($user->getId(), new OidcClaims(self::ISSUER, 'sub-' . uniqid(), 'newer'));
    $older = $this->link($user->getId(), new OidcClaims('https://other.example.test', 'sub-' . uniqid(), 'older'));
    $older->setCreatedAt($newer->getCreatedAt() - 100);
    Factory::getOidcIdentityFactory()->update($older);
    
    $list = OidcIdentityUtils::listForUser($user->getId());
    $this->assertSame([$older->getId(), $newer->getId()], array_map(fn($i) => $i->getId(), $list));
  }
  
  /**
   * @throws Exception
   */
  public function testDeletingUserRemovesIdentities(): void {
    // Deliberately not registered for teardown: the test deletes the user itself
    $name = 'oidc_del_' . uniqid();
    $user = UserUtils::createUser($name, $name . '@example.com', $this->createRightGroup()->getId(), $this->adminUser);
    $claims = new OidcClaims(self::ISSUER, 'sub-' . uniqid(), 'alice');
    OidcIdentityUtils::link($user->getId(), $claims);
    
    UserUtils::deleteUser($user->getId(), $this->adminUser);
    
    $this->assertNull(OidcIdentityUtils::find($claims->issuer, $claims->subject));
  }
  
  /**
   * @throws Exception
   */
  public function testTouchSetsLastUsedAt(): void {
    $user = $this->createUser('oidc_touch');
    $claims = new OidcClaims(self::ISSUER, 'sub-' . uniqid(), 'alice');
    $identity = $this->link($user->getId(), $claims);
    $before = time();
    
    OidcIdentityUtils::touch($identity);
    
    $this->assertGreaterThanOrEqual($before, $identity->getLastUsedAt());
    $stored = OidcIdentityUtils::find($claims->issuer, $claims->subject);
    $this->assertGreaterThanOrEqual($before, $stored->getLastUsedAt());
  }
  
  /**
   * @throws Exception
   */
  public function testInsertCollisionResolvesByOwner(): void {
    $alice = $this->createUser('oidc_a');
    $bob = $this->createUser('oidc_b');
    $claims = new OidcClaims(self::ISSUER, 'sub-' . uniqid(), 'alice');
    $row = $this->link($alice->getId(), $claims);
    $collision = new PDOException('Duplicate entry');
    $collision->errorInfo = ['23000', 1062, 'Duplicate entry'];
    
    $this->assertSame($row->getId(), OidcIdentityUtils::resolveInsertFailure($alice->getId(), $claims, $collision)->getId());
    $this->expectException(OidcAlreadyLinkedException::class);
    OidcIdentityUtils::resolveInsertFailure($bob->getId(), $claims, $collision);
  }
  
  /**
   * @throws Exception
   */
  public function testNonConstraintInsertFailureIsRethrown(): void {
    $user = $this->createUser('oidc_x');
    $claims = new OidcClaims(self::ISSUER, 'sub-' . uniqid(), 'alice');
    $this->link($user->getId(), $claims);
    $other = new PDOException('Connection lost');
    $other->errorInfo = ['HY000', 2006, 'gone'];
    
    $this->expectException(PDOException::class);
    OidcIdentityUtils::resolveInsertFailure($user->getId(), $claims, $other);
  }
}
