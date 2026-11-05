<?php

namespace Hashtopolis\dba\models;

use Hashtopolis\dba\AbstractModelFactory;

/**
 * @extends AbstractModelFactory<OidcIdentity>
 */
class OidcIdentityFactory extends AbstractModelFactory {
  function getModelName(): string {
    return "OidcIdentity";
  }
  
  function getModelTable(): string {
    return "OidcIdentity";
  }

  function isMapping(): bool {
    return False;
  }
  
  function isCachable(): bool {
    return false;
  }
  
  function getCacheValidTime(): int {
    return -1;
  }
  
  /**
   * @return OidcIdentity
   */
  function getNullObject(): OidcIdentity {
    return new OidcIdentity(-1, null, null, null, null, null, null);
  }
  
  /**
   * @param array $dict
   * @return OidcIdentity
   */
  function createObjectFromDict(array $dict): OidcIdentity {
    $conv = [];
    foreach ($dict as $key => $val) {
      $conv[strtolower($key)] = $val;
    }
    $dict = $conv;
    return new OidcIdentity($dict['oidcidentityid'], $dict['userid'], $dict['issuer'], $dict['subject'], $dict['label'], $dict['createdat'], $dict['lastusedat']);
  }
}
