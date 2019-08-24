/*
 * This file is generated by jOOQ.
 */
package ch.rasc.webauthn.db;

import javax.annotation.Generated;

import org.jooq.ForeignKey;
import org.jooq.Identity;
import org.jooq.UniqueKey;
import org.jooq.impl.Internal;

import ch.rasc.webauthn.db.tables.AppUser;
import ch.rasc.webauthn.db.tables.Credentials;
import ch.rasc.webauthn.db.tables.records.AppUserRecord;
import ch.rasc.webauthn.db.tables.records.CredentialsRecord;

/**
 * A class modelling foreign key relationships and constraints of tables of the
 * <code></code> schema.
 */
@Generated(value = { "http://www.jooq.org", "jOOQ version:3.11.11" },
    comments = "This class is generated by jOOQ")
@SuppressWarnings({ "all", "unchecked", "rawtypes" })
public class Keys {

  // -------------------------------------------------------------------------
  // IDENTITY definitions
  // -------------------------------------------------------------------------

  public static final Identity<AppUserRecord, Long> IDENTITY_APP_USER = Identities0.IDENTITY_APP_USER;

  // -------------------------------------------------------------------------
  // UNIQUE and PRIMARY KEY definitions
  // -------------------------------------------------------------------------

  public static final UniqueKey<AppUserRecord> CONSTRAINT_7 = UniqueKeys0.CONSTRAINT_7;
  public static final UniqueKey<AppUserRecord> CONSTRAINT_76 = UniqueKeys0.CONSTRAINT_76;
  public static final UniqueKey<CredentialsRecord> CONSTRAINT_9 = UniqueKeys0.CONSTRAINT_9;

  // -------------------------------------------------------------------------
  // FOREIGN KEY definitions
  // -------------------------------------------------------------------------

  public static final ForeignKey<CredentialsRecord, AppUserRecord> CONSTRAINT_91 = ForeignKeys0.CONSTRAINT_91;

  // -------------------------------------------------------------------------
  // [#1459] distribute members to avoid static initialisers > 64kb
  // -------------------------------------------------------------------------

  private static class Identities0 {
    public static Identity<AppUserRecord, Long> IDENTITY_APP_USER = Internal
        .createIdentity(AppUser.APP_USER, AppUser.APP_USER.ID);
  }

  private static class UniqueKeys0 {
    public static final UniqueKey<AppUserRecord> CONSTRAINT_7 = Internal
        .createUniqueKey(AppUser.APP_USER, "CONSTRAINT_7", AppUser.APP_USER.ID);
    public static final UniqueKey<AppUserRecord> CONSTRAINT_76 = Internal
        .createUniqueKey(AppUser.APP_USER, "CONSTRAINT_76", AppUser.APP_USER.USERNAME);
    public static final UniqueKey<CredentialsRecord> CONSTRAINT_9 = Internal
        .createUniqueKey(Credentials.CREDENTIALS, "CONSTRAINT_9",
            Credentials.CREDENTIALS.ID, Credentials.CREDENTIALS.APP_USER_ID);
  }

  private static class ForeignKeys0 {
    public static final ForeignKey<CredentialsRecord, AppUserRecord> CONSTRAINT_91 = Internal
        .createForeignKey(ch.rasc.webauthn.db.Keys.CONSTRAINT_7, Credentials.CREDENTIALS,
            "CONSTRAINT_91", Credentials.CREDENTIALS.APP_USER_ID);
  }
}
