<?php

namespace Hashtopolis\dba\models;

use Hashtopolis\dba\AbstractModel;

class OidcAuthRequest extends AbstractModel {
  private ?int $oidcAuthRequestId;
  private ?string $stateHash;
  private ?string $purpose;
  private ?int $userId;
  private ?string $codeVerifier;
  private ?string $nonce;
  private ?string $returnTo;
  private ?string $issuer;
  private ?string $subject;
  private ?string $label;
  private ?int $expiresAt;
  private ?int $usedAt;
  
  function __construct(?int $oidcAuthRequestId, ?string $stateHash, ?string $purpose, ?int $userId, ?string $codeVerifier, ?string $nonce, ?string $returnTo, ?string $issuer, ?string $subject, ?string $label, ?int $expiresAt, ?int $usedAt) {
    $this->oidcAuthRequestId = $oidcAuthRequestId;
    $this->stateHash = $stateHash;
    $this->purpose = $purpose;
    $this->userId = $userId;
    $this->codeVerifier = $codeVerifier;
    $this->nonce = $nonce;
    $this->returnTo = $returnTo;
    $this->issuer = $issuer;
    $this->subject = $subject;
    $this->label = $label;
    $this->expiresAt = $expiresAt;
    $this->usedAt = $usedAt;
  }
  
  function getKeyValueDict(): array {
    $dict = array();
    $dict['oidcAuthRequestId'] = $this->oidcAuthRequestId;
    $dict['stateHash'] = $this->stateHash;
    $dict['purpose'] = $this->purpose;
    $dict['userId'] = $this->userId;
    $dict['codeVerifier'] = $this->codeVerifier;
    $dict['nonce'] = $this->nonce;
    $dict['returnTo'] = $this->returnTo;
    $dict['issuer'] = $this->issuer;
    $dict['subject'] = $this->subject;
    $dict['label'] = $this->label;
    $dict['expiresAt'] = $this->expiresAt;
    $dict['usedAt'] = $this->usedAt;
    
    return $dict;
  }
  
  static function getFeatures(): array {
    $dict = array();
    $dict['oidcAuthRequestId'] = ['read_only' => True, "type" => "int", "subtype" => "unset", "choices" => "unset", "null" => False, "pk" => True, "protected" => True, "private" => False, "alias" => "oidcAuthRequestId", "public" => False, "dba_mapping" => False];
    $dict['stateHash'] = ['read_only' => True, "type" => "str(64)", "subtype" => "unset", "choices" => "unset", "null" => False, "pk" => False, "protected" => True, "private" => True, "alias" => "stateHash", "public" => False, "dba_mapping" => False];
    $dict['purpose'] = ['read_only' => True, "type" => "str(16)", "subtype" => "unset", "choices" => "unset", "null" => False, "pk" => False, "protected" => True, "private" => False, "alias" => "purpose", "public" => False, "dba_mapping" => False];
    $dict['userId'] = ['read_only' => True, "type" => "int", "subtype" => "unset", "choices" => "unset", "null" => True, "pk" => False, "protected" => True, "private" => False, "alias" => "userId", "public" => False, "dba_mapping" => False];
    $dict['codeVerifier'] = ['read_only' => True, "type" => "str(128)", "subtype" => "unset", "choices" => "unset", "null" => True, "pk" => False, "protected" => True, "private" => True, "alias" => "codeVerifier", "public" => False, "dba_mapping" => False];
    $dict['nonce'] = ['read_only' => True, "type" => "str(64)", "subtype" => "unset", "choices" => "unset", "null" => True, "pk" => False, "protected" => True, "private" => False, "alias" => "nonce", "public" => False, "dba_mapping" => False];
    $dict['returnTo'] = ['read_only' => True, "type" => "str(255)", "subtype" => "unset", "choices" => "unset", "null" => False, "pk" => False, "protected" => True, "private" => False, "alias" => "returnTo", "public" => False, "dba_mapping" => False];
    $dict['issuer'] = ['read_only' => True, "type" => "str(255)", "subtype" => "unset", "choices" => "unset", "null" => True, "pk" => False, "protected" => True, "private" => False, "alias" => "issuer", "public" => False, "dba_mapping" => False];
    $dict['subject'] = ['read_only' => True, "type" => "str(255)", "subtype" => "unset", "choices" => "unset", "null" => True, "pk" => False, "protected" => True, "private" => False, "alias" => "subject", "public" => False, "dba_mapping" => False];
    $dict['label'] = ['read_only' => True, "type" => "str(255)", "subtype" => "unset", "choices" => "unset", "null" => True, "pk" => False, "protected" => True, "private" => False, "alias" => "label", "public" => False, "dba_mapping" => False];
    $dict['expiresAt'] = ['read_only' => True, "type" => "int64", "subtype" => "unset", "choices" => "unset", "null" => False, "pk" => False, "protected" => True, "private" => False, "alias" => "expiresAt", "public" => False, "dba_mapping" => False];
    $dict['usedAt'] = ['read_only' => True, "type" => "int64", "subtype" => "unset", "choices" => "unset", "null" => True, "pk" => False, "protected" => True, "private" => False, "alias" => "usedAt", "public" => False, "dba_mapping" => False];

    return $dict;
  }

  function getPrimaryKey(): string {
    return "oidcAuthRequestId";
  }
  
  function getPrimaryKeyValue(): ?int {
    return $this->oidcAuthRequestId;
  }
  
  function getId(): ?int {
    return $this->oidcAuthRequestId;
  }
  
  function setId($id): void {
    $this->oidcAuthRequestId = $id;
  }
  
  /**
   * Used to serialize the data contained in the model
   * @return array
   */
  public function expose(): array {
    return get_object_vars($this);
  }
  
  function getStateHash(): ?string {
    return $this->stateHash;
  }
  
  function setStateHash(?string $stateHash): void {
    $this->stateHash = $stateHash;
  }
  
  function getPurpose(): ?string {
    return $this->purpose;
  }
  
  function setPurpose(?string $purpose): void {
    $this->purpose = $purpose;
  }
  
  function getUserId(): ?int {
    return $this->userId;
  }
  
  function setUserId(?int $userId): void {
    $this->userId = $userId;
  }
  
  function getCodeVerifier(): ?string {
    return $this->codeVerifier;
  }
  
  function setCodeVerifier(?string $codeVerifier): void {
    $this->codeVerifier = $codeVerifier;
  }
  
  function getNonce(): ?string {
    return $this->nonce;
  }
  
  function setNonce(?string $nonce): void {
    $this->nonce = $nonce;
  }
  
  function getReturnTo(): ?string {
    return $this->returnTo;
  }
  
  function setReturnTo(?string $returnTo): void {
    $this->returnTo = $returnTo;
  }
  
  function getIssuer(): ?string {
    return $this->issuer;
  }
  
  function setIssuer(?string $issuer): void {
    $this->issuer = $issuer;
  }
  
  function getSubject(): ?string {
    return $this->subject;
  }
  
  function setSubject(?string $subject): void {
    $this->subject = $subject;
  }
  
  function getLabel(): ?string {
    return $this->label;
  }
  
  function setLabel(?string $label): void {
    $this->label = $label;
  }
  
  function getExpiresAt(): ?int {
    return $this->expiresAt;
  }
  
  function setExpiresAt(?int $expiresAt): void {
    $this->expiresAt = $expiresAt;
  }
  
  function getUsedAt(): ?int {
    return $this->usedAt;
  }
  
  function setUsedAt(?int $usedAt): void {
    $this->usedAt = $usedAt;
  }
  
  const OIDC_AUTH_REQUEST_ID = "oidcAuthRequestId";
  const STATE_HASH = "stateHash";
  const PURPOSE = "purpose";
  const USER_ID = "userId";
  const CODE_VERIFIER = "codeVerifier";
  const NONCE = "nonce";
  const RETURN_TO = "returnTo";
  const ISSUER = "issuer";
  const SUBJECT = "subject";
  const LABEL = "label";
  const EXPIRES_AT = "expiresAt";
  const USED_AT = "usedAt";

  const PERM_CREATE = "permOidcAuthRequestCreate";
  const PERM_READ = "permOidcAuthRequestRead";
  const PERM_UPDATE = "permOidcAuthRequestUpdate";
  const PERM_DELETE = "permOidcAuthRequestDelete";
}
