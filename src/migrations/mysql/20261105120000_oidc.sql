-- OpenID Connect single sign-on.
-- issuer and subject are case-sensitive opaque strings, so they use a binary collation; the default
-- case-insensitive one would make different identities collide in the unique key.
-- OidcIdentity links a Hashtopolis user to an (issuer, subject) pair at an identity provider. Identities
-- are removed together with the user.
CREATE TABLE `OidcIdentity` (
  `oidcIdentityId` int NOT NULL AUTO_INCREMENT,
  `userId` int NOT NULL,
  `issuer` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `subject` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `label` varchar(255) NOT NULL,
  `createdAt` bigint NOT NULL,
  `lastUsedAt` bigint DEFAULT NULL,
  PRIMARY KEY (`oidcIdentityId`),
  UNIQUE KEY `uq_oidcIdentity_issuer_subject` (`issuer`, `subject`),
  KEY `idx_oidcIdentity_userId` (`userId`),
  CONSTRAINT `fk_oidcIdentity_user` FOREIGN KEY (`userId`) REFERENCES `htp_User` (`userId`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Short-lived, single-use state of a sign-in in progress. Only the SHA-256 hash of the state value is stored.
CREATE TABLE `OidcAuthRequest` (
  `oidcAuthRequestId` int NOT NULL AUTO_INCREMENT,
  `stateHash` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `purpose` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `userId` int DEFAULT NULL,
  `codeVerifier` varchar(128) DEFAULT NULL,
  `nonce` varchar(64) DEFAULT NULL,
  `returnTo` varchar(255) NOT NULL,
  `issuer` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
  `subject` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
  `label` varchar(255) DEFAULT NULL,
  `expiresAt` bigint NOT NULL,
  `usedAt` bigint DEFAULT NULL,
  PRIMARY KEY (`oidcAuthRequestId`),
  UNIQUE KEY `uq_oidcAuthRequest_stateHash` (`stateHash`),
  KEY `idx_oidcAuthRequest_expiresAt` (`expiresAt`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
