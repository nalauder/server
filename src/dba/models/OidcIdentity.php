<?php

namespace Hashtopolis\dba\models;

use Hashtopolis\dba\AbstractModel;

class OidcIdentity extends AbstractModel {
  private ?int $oidcIdentityId;
  private ?int $userId;
  private ?string $issuer;
  private ?string $subject;
  private ?string $label;
  private ?int $createdAt;
  private ?int $lastUsedAt;
  
  function __construct(?int $oidcIdentityId, ?int $userId, ?string $issuer, ?string $subject, ?string $label, ?int $createdAt, ?int $lastUsedAt) {
    $this->oidcIdentityId = $oidcIdentityId;
    $this->userId = $userId;
    $this->issuer = $issuer;
    $this->subject = $subject;
    $this->label = $label;
    $this->createdAt = $createdAt;
    $this->lastUsedAt = $lastUsedAt;
  }
  
  function getKeyValueDict(): array {
    $dict = array();
    $dict['oidcIdentityId'] = $this->oidcIdentityId;
    $dict['userId'] = $this->userId;
    $dict['issuer'] = $this->issuer;
    $dict['subject'] = $this->subject;
    $dict['label'] = $this->label;
    $dict['createdAt'] = $this->createdAt;
    $dict['lastUsedAt'] = $this->lastUsedAt;
    
    return $dict;
  }
  
  static function getFeatures(): array {
    $dict = array();
    $dict['oidcIdentityId'] = ['read_only' => True, "type" => "int", "subtype" => "unset", "choices" => "unset", "null" => False, "pk" => True, "protected" => True, "private" => False, "alias" => "oidcIdentityId", "public" => False, "dba_mapping" => False];
    $dict['userId'] = ['read_only' => True, "type" => "int", "subtype" => "unset", "choices" => "unset", "null" => False, "pk" => False, "protected" => False, "private" => False, "alias" => "userId", "public" => False, "dba_mapping" => False];
    $dict['issuer'] = ['read_only' => True, "type" => "str(255)", "subtype" => "unset", "choices" => "unset", "null" => False, "pk" => False, "protected" => False, "private" => False, "alias" => "issuer", "public" => False, "dba_mapping" => False];
    $dict['subject'] = ['read_only' => True, "type" => "str(255)", "subtype" => "unset", "choices" => "unset", "null" => False, "pk" => False, "protected" => True, "private" => False, "alias" => "subject", "public" => False, "dba_mapping" => False];
    $dict['label'] = ['read_only' => False, "type" => "str(255)", "subtype" => "unset", "choices" => "unset", "null" => False, "pk" => False, "protected" => False, "private" => False, "alias" => "label", "public" => False, "dba_mapping" => False];
    $dict['createdAt'] = ['read_only' => True, "type" => "int64", "subtype" => "unset", "choices" => "unset", "null" => False, "pk" => False, "protected" => False, "private" => False, "alias" => "createdAt", "public" => False, "dba_mapping" => False];
    $dict['lastUsedAt'] = ['read_only' => False, "type" => "int64", "subtype" => "unset", "choices" => "unset", "null" => True, "pk" => False, "protected" => False, "private" => False, "alias" => "lastUsedAt", "public" => False, "dba_mapping" => False];

    return $dict;
  }

  function getPrimaryKey(): string {
    return "oidcIdentityId";
  }
  
  function getPrimaryKeyValue(): ?int {
    return $this->oidcIdentityId;
  }
  
  function getId(): ?int {
    return $this->oidcIdentityId;
  }
  
  function setId($id): void {
    $this->oidcIdentityId = $id;
  }
  
  /**
   * Used to serialize the data contained in the model
   * @return array
   */
  public function expose(): array {
    return get_object_vars($this);
  }
  
  function getUserId(): ?int {
    return $this->userId;
  }
  
  function setUserId(?int $userId): void {
    $this->userId = $userId;
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
  
  function getCreatedAt(): ?int {
    return $this->createdAt;
  }
  
  function setCreatedAt(?int $createdAt): void {
    $this->createdAt = $createdAt;
  }
  
  function getLastUsedAt(): ?int {
    return $this->lastUsedAt;
  }
  
  function setLastUsedAt(?int $lastUsedAt): void {
    $this->lastUsedAt = $lastUsedAt;
  }
  
  const OIDC_IDENTITY_ID = "oidcIdentityId";
  const USER_ID = "userId";
  const ISSUER = "issuer";
  const SUBJECT = "subject";
  const LABEL = "label";
  const CREATED_AT = "createdAt";
  const LAST_USED_AT = "lastUsedAt";

  const PERM_CREATE = "permOidcIdentityCreate";
  const PERM_READ = "permOidcIdentityRead";
  const PERM_UPDATE = "permOidcIdentityUpdate";
  const PERM_DELETE = "permOidcIdentityDelete";
}
