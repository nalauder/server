<?php

namespace Hashtopolis\inc;

use Hashtopolis\dba\Factory;
use Hashtopolis\dba\models\LogEntry;
use Hashtopolis\dba\models\User;
use Hashtopolis\dba\OrderFilter;
use Hashtopolis\dba\QueryFilter;
use Hashtopolis\inc\apiv2\auth\oidc\OidcConfig;
use Hashtopolis\inc\defines\DForgotAction;
use Hashtopolis\inc\defines\DLogEntry;
use Hashtopolis\inc\handlers\ForgotHandler;
use Hashtopolis\TestBase;
use Override;

require_once(dirname(__FILE__) . '/../TestBase.php');
require_once(dirname(__FILE__) . '/../../../src/inc/startup/include.php');

/**
 * The legacy web UI's password login and password reset obey HASHTOPOLIS_LOCAL_LOGIN_ENABLED like the API does.
 */
final class LegacyLocalLoginTest extends TestBase {
  private const PASSWORD = 'legacy-login-pass-1';

  private int $lastLogId;

  #[Override]
  protected function setUp(): void {
    parent::setUp();
    $entry = Factory::getLogEntryFactory()->filter([
      Factory::ORDER => new OrderFilter(LogEntry::LOG_ENTRY_ID, "DESC LIMIT 1")
    ], true);
    $this->lastLogId = $entry instanceof LogEntry ? $entry->getId() : 0;
    UI::add('messages', []);
    OidcConfig::setInstance(new OidcConfig([
      'HASHTOPOLIS_OIDC_ISSUER' => 'https://idp.example.test/realms/test',
      'HASHTOPOLIS_OIDC_CLIENT_ID' => 'hashtopolis',
      'HASHTOPOLIS_OIDC_CLIENT_SECRET' => 'test-client-secret',
      'HASHTOPOLIS_LOCAL_LOGIN_ENABLED' => 'false',
    ]));
  }

  #[Override]
  protected function tearDown(): void {
    OidcConfig::setInstance(null);
    unset($_POST['username'], $_POST['email']);
    UI::add('messages', []);
    Factory::getLogEntryFactory()->massDeletion([
      Factory::FILTER => new QueryFilter(LogEntry::LOG_ENTRY_ID, $this->lastLogId, ">")
    ]);
    parent::tearDown();
  }

  private function userWithPassword(): User {
    $user = $this->createUser('legacy_login');
    return Factory::getUserFactory()->set($user, User::PASSWORD_HASH, Encryption::passwordHash(self::PASSWORD, $user->getPasswordSalt()));
  }

  /**
   * @return LogEntry[] warnings written since setUp (creating the test user logs too)
   */
  private function newWarnings(): array {
    return Factory::getLogEntryFactory()->filter([
      Factory::FILTER => [
        new QueryFilter(LogEntry::LOG_ENTRY_ID, $this->lastLogId, ">"),
        new QueryFilter(LogEntry::LEVEL, DLogEntry::WARN, "="),
      ]
    ]);
  }

  /**
   * @return string[] the messages the handler queued for the page
   */
  private function uiMessages(): array {
    return array_map(fn($m) => $m->getVal('message'), UI::get('messages') ?: []);
  }

  public function testLoginRefusedWithCorrectPasswordWhenLocalLoginDisabled(): void {
    $user = $this->userWithPassword();

    $this->assertFalse(Login::getInstance()->login($user->getUsername(), self::PASSWORD));

    $this->assertFalse(Login::getInstance()->isLoggedin());
    $entries = $this->newWarnings();
    $this->assertCount(1, $entries);
    $this->assertStringContainsString('local login is disabled', $entries[0]->getMessage());
    $this->assertStringNotContainsString($user->getUsername(), $entries[0]->getMessage());
  }

  public function testLoginRefusalIsTheSameForAnUnknownUser(): void {
    $user = $this->userWithPassword();
    $this->assertFalse(Login::getInstance()->login($user->getUsername(), self::PASSWORD));
    $known = $this->newWarnings();

    $this->assertFalse(Login::getInstance()->login('no_such_user_' . uniqid(), self::PASSWORD));

    $all = $this->newWarnings();
    $this->assertCount(2, $all);
    $this->assertSame($known[0]->getMessage(), $all[1]->getMessage());
    $this->assertSame($known[0]->getIssuerId(), $all[1]->getIssuerId());
  }

  public function testForgotPasswordRefusedWhenLocalLoginDisabled(): void {
    $user = $this->userWithPassword();
    $mailed = false;
    \hashtopolis_set_test_mock('mail', function () use (&$mailed) {
      $mailed = true;
      return true;
    });
    $_POST['username'] = $user->getUsername();
    $_POST['email'] = $user->getEmail();

    (new ForgotHandler())->handle(DForgotAction::RESET);

    $this->assertSame([ForgotHandler::LOCAL_LOGIN_DISABLED_MESSAGE], $this->uiMessages());
    $this->assertFalse($mailed);
    $after = Factory::getUserFactory()->get($user->getId());
    $this->assertSame($user->getPasswordHash(), $after->getPasswordHash());
  }

  public function testForgotPasswordRefusalIsTheSameForAnUnknownUser(): void {
    $_POST['username'] = 'no_such_user_' . uniqid();
    $_POST['email'] = 'nobody@example.test';

    (new ForgotHandler())->handle(DForgotAction::RESET);

    $this->assertSame([ForgotHandler::LOCAL_LOGIN_DISABLED_MESSAGE], $this->uiMessages());
  }
}
