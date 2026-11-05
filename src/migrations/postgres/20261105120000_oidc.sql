-- OpenID Connect single sign-on.
-- oidcidentity links a Hashtopolis user to an (issuer, subject) pair at an identity provider. Identities
-- are removed together with the user.
CREATE TABLE oidcidentity (
  oidcidentityid integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  userid integer NOT NULL,
  issuer varchar(255) NOT NULL,
  subject varchar(255) NOT NULL,
  label varchar(255) NOT NULL,
  createdat bigint NOT NULL,
  lastusedat bigint DEFAULT NULL,
  CONSTRAINT uq_oidcidentity_issuer_subject UNIQUE (issuer, subject),
  CONSTRAINT oidcidentity_user_fkey FOREIGN KEY (userid) REFERENCES htp_user(userid) ON DELETE CASCADE
);

CREATE INDEX oidcidentity_userid_idx ON oidcidentity(userid);

-- Short-lived, single-use state of a sign-in in progress. Only the SHA-256 hash of the state value is stored.
CREATE TABLE oidcauthrequest (
  oidcauthrequestid integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  statehash char(64) NOT NULL,
  purpose varchar(16) NOT NULL,
  userid integer DEFAULT NULL,
  codeverifier varchar(128) DEFAULT NULL,
  nonce varchar(64) DEFAULT NULL,
  returnto varchar(255) NOT NULL,
  issuer varchar(255) DEFAULT NULL,
  subject varchar(255) DEFAULT NULL,
  label varchar(255) DEFAULT NULL,
  expiresat bigint NOT NULL,
  usedat bigint DEFAULT NULL,
  CONSTRAINT uq_oidcauthrequest_statehash UNIQUE (statehash)
);

CREATE INDEX oidcauthrequest_expiresat_idx ON oidcauthrequest(expiresat);
