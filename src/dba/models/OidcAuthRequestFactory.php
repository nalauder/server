<?php

namespace Hashtopolis\dba\models;

use Hashtopolis\dba\AbstractModelFactory;

/**
 * @extends AbstractModelFactory<OidcAuthRequest>
 */
class OidcAuthRequestFactory extends AbstractModelFactory {
  function getModelName(): string {
    return "OidcAuthRequest";
  }
  
  function getModelTable(): string {
    return "OidcAuthRequest";
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
   * @return OidcAuthRequest
   */
  function getNullObject(): OidcAuthRequest {
    return new OidcAuthRequest(-1, null, null, null, null, null, null, null, null, null, null, null);
  }
  
  /**
   * @param array $dict
   * @return OidcAuthRequest
   */
  function createObjectFromDict(array $dict): OidcAuthRequest {
    $conv = [];
    foreach ($dict as $key => $val) {
      $conv[strtolower($key)] = $val;
    }
    $dict = $conv;
    return new OidcAuthRequest($dict['oidcauthrequestid'], $dict['statehash'], $dict['purpose'], $dict['userid'], $dict['codeverifier'], $dict['nonce'], $dict['returnto'], $dict['issuer'], $dict['subject'], $dict['label'], $dict['expiresat'], $dict['usedat']);
  }
}
