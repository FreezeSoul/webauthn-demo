package ch.rasc.webauthn.security;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.jooq.DSLContext;
import org.jooq.exception.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;

import ch.rasc.webauthn.Application;
import static ch.rasc.webauthn.db.tables.AppUser.APP_USER;
import static ch.rasc.webauthn.db.tables.Credentials.CREDENTIALS;
import ch.rasc.webauthn.security.dto.AssertionFinishRequest;
import ch.rasc.webauthn.security.dto.AssertionStartResponse;
import ch.rasc.webauthn.security.dto.RegistrationFinishRequest;
import ch.rasc.webauthn.security.dto.RegistrationStartResponse;
import ch.rasc.webauthn.security.dto.RegistrationStartResponse.Mode;
import ch.rasc.webauthn.util.Base58;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

@RestController
@Validated
public class AuthController {

  private final DSLContext dsl;

  private final Cache<String, PendingRegistration> registrationCache;

  private final Cache<String, AssertionStartResponse> assertionCache;

  private final JooqCredentialRepository credentialRepository;

  private final SecurityContextRepository securityContextRepository;

  private final RelyingParty relyingParty;

  private final TransactionTemplate transactionTemplate;

  private final SecureRandom random;

  public AuthController(DSLContext dsl, JooqCredentialRepository credentialRepository,
      RelyingParty relyingParty, SecurityContextRepository securityContextRepository,
      TransactionTemplate transactionTemplate) {
    this.dsl = dsl;
    this.credentialRepository = credentialRepository;
    this.securityContextRepository = securityContextRepository;
    this.relyingParty = relyingParty;
    this.transactionTemplate = transactionTemplate;
    this.registrationCache = Caffeine.newBuilder().maximumSize(1000)
        .expireAfterWrite(5, TimeUnit.MINUTES).build();
    this.assertionCache = Caffeine.newBuilder().maximumSize(1000)
        .expireAfterWrite(5, TimeUnit.MINUTES).build();
    this.random = new SecureRandom();
  }

  @GetMapping("/authenticate")
  @ResponseStatus(code = HttpStatus.NO_CONTENT)
  public void authenticate() {
    // nothing here
  }

  @GetMapping("/csrf")
  public CsrfToken csrf(CsrfToken csrfToken) {
    return csrfToken;
  }

  @PostMapping("/registration/start")
  public RegistrationStartResponse registrationStart(
      @RequestParam(name = "username", required = false) String username,
      @RequestParam(name = "recoveryToken", required = false) String recoveryToken) {

    Long userId = null;
    byte[] recoveryTokenBytes = null;
    String name = null;
    Mode mode = null;

    String normalizedUsername = username == null ? null : username.strip();
    String normalizedRecoveryToken = recoveryToken == null ? null
        : recoveryToken.strip();
    boolean hasUsername = normalizedUsername != null && !normalizedUsername.isEmpty();
    boolean hasRecoveryToken = normalizedRecoveryToken != null
        && !normalizedRecoveryToken.isEmpty();

    if (hasUsername == hasRecoveryToken) {
      return new RegistrationStartResponse(
          RegistrationStartResponse.Status.INVALID_REQUEST);
    }

    if (hasUsername) {
      if (normalizedUsername.length() > 255) {
        return new RegistrationStartResponse(
            RegistrationStartResponse.Status.INVALID_REQUEST);
      }

      int count = this.dsl.selectCount().from(APP_USER)
          .where(APP_USER.USERNAME.equalIgnoreCase(normalizedUsername))
          .fetchOne(0, int.class);
      if (count > 0) {
        return new RegistrationStartResponse(
            RegistrationStartResponse.Status.USERNAME_TAKEN);
      }

      name = normalizedUsername;
      mode = Mode.NEW;
    }
    else {
      try {
        recoveryTokenBytes = Base58.decode(normalizedRecoveryToken);
      }
      catch (Exception e) {
        return new RegistrationStartResponse(
            RegistrationStartResponse.Status.TOKEN_INVALID);
      }

      if (recoveryTokenBytes.length != 16) {
        return new RegistrationStartResponse(
            RegistrationStartResponse.Status.TOKEN_INVALID);
      }

      var record = this.dsl.select(APP_USER.ID, APP_USER.USERNAME).from(APP_USER)
          .where(APP_USER.RECOVERY_TOKEN.eq(recoveryTokenBytes)).fetchOne();

      if (record == null) {
        return new RegistrationStartResponse(
            RegistrationStartResponse.Status.TOKEN_INVALID);
      }

      userId = record.get(APP_USER.ID);
      name = record.get(APP_USER.USERNAME);
      mode = Mode.RECOVERY;
    }

    byte[] webAuthnIdBytes = new byte[64];
    this.random.nextBytes(webAuthnIdBytes);
    ByteArray webAuthnId = new ByteArray(webAuthnIdBytes);

    PublicKeyCredentialCreationOptions credentialCreation = this.relyingParty
        .startRegistration(StartRegistrationOptions.builder()
            .user(UserIdentity.builder().name(name).displayName(name).id(webAuthnId)
                .build())
            .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                .residentKey(ResidentKeyRequirement.REQUIRED)
                .userVerification(UserVerificationRequirement.PREFERRED).build())
            .build());

    RegistrationStartResponse startResponse = new RegistrationStartResponse(mode,
        newRequestId(), credentialCreation);

    this.registrationCache.put(startResponse.getRegistrationId(),
        new PendingRegistration(startResponse, userId,
            recoveryTokenBytes == null ? null : new ByteArray(recoveryTokenBytes)));

    return startResponse;
  }

  @PostMapping("/registration/finish")
  public ResponseEntity<String> registrationFinish(
      @Valid @RequestBody RegistrationFinishRequest finishRequest) {

    PendingRegistration pending = this.registrationCache.asMap()
        .remove(finishRequest.getRegistrationId());
    if (pending == null) {
      Application.log.warn("Expired or already consumed registration request");
      return ResponseEntity.badRequest().build();
    }

    RegistrationResult registrationResult;
    try {
      registrationResult = this.relyingParty
          .finishRegistration(FinishRegistrationOptions.builder()
              .request(pending.startResponse()
                  .getPublicKeyCredentialCreationOptions())
              .response(finishRequest.getCredential()).build());
    }
    catch (RegistrationFailedException | IllegalArgumentException e) {
      Application.log.warn("Registration verification failed: {}", e.getMessage());
      return ResponseEntity.badRequest().build();
    }

    try {
      String newRecoveryToken = this.transactionTemplate.execute(status ->
          persistRegistration(pending, registrationResult, finishRequest));
      if (newRecoveryToken == null) {
        return ResponseEntity.status(HttpStatus.CONFLICT).build();
      }
      return ResponseEntity.ok(newRecoveryToken);
    }
    catch (DataAccessException | org.springframework.dao.DataAccessException e) {
      Application.log.warn("Could not persist registration: {}", e.getMessage());
      return ResponseEntity.status(HttpStatus.CONFLICT).build();
    }
  }

  @PostMapping("/assertion/start")
  public AssertionStartResponse start() {
    AssertionRequest assertionRequest = this.relyingParty
        .startAssertion(StartAssertionOptions.builder()
            .userVerification(UserVerificationRequirement.PREFERRED).build());

    AssertionStartResponse response = new AssertionStartResponse(newRequestId(),
        assertionRequest);

    this.assertionCache.put(response.getAssertionId(), response);
    return response;
  }

  @PostMapping("/assertion/finish")
  public boolean finish(@Valid @RequestBody AssertionFinishRequest finishRequest,
      HttpServletRequest request, HttpServletResponse response) {

    AssertionStartResponse startResponse = this.assertionCache.asMap()
        .remove(finishRequest.getAssertionId());

    if (startResponse == null) {
      Application.log.warn("Expired or already consumed assertion request");
      return false;
    }

    try {
      AssertionResult result = this.relyingParty.finishAssertion(
          FinishAssertionOptions.builder().request(startResponse.getAssertionRequest())
              .response(finishRequest.getCredential()).build());

      if (result.isSuccess()) {
        if (!this.credentialRepository.updateSignatureCount(result)) {
          Application.log.error(
              "Failed to update signature count for user \"{}\", credential \"{}\"",
              result.getUsername(), finishRequest.getCredential().getId());
        }

        var appUserRecordResult = this.dsl.select(APP_USER.asterisk()).from(APP_USER)
            .innerJoin(CREDENTIALS).onKey()
            .where(CREDENTIALS.WEBAUTHN_USER_ID
                .eq(result.getCredential().getUserHandle().getBytes()))
            .fetchOne();

        if (appUserRecordResult != null) {
          var appUserRecord = appUserRecordResult.into(APP_USER);
          AppUserDetail userDetail = new AppUserDetail(appUserRecord,
              new SimpleGrantedAuthority("USER"));
          AppUserAuthentication auth = new AppUserAuthentication(userDetail);
          HttpSession existingSession = request.getSession(false);
          if (existingSession != null) {
            request.changeSessionId();
          }
          SecurityContext context = SecurityContextHolder.createEmptyContext();
          context.setAuthentication(auth);
          SecurityContextHolder.setContext(context);
          this.securityContextRepository.saveContext(context, request, response);
          return true;
        }
      }
    }
    catch (AssertionFailedException | IllegalArgumentException e) {
      Application.log.warn("Assertion verification failed: {}", e.getMessage());
    }

    return false;
  }

  private String persistRegistration(PendingRegistration pending,
      RegistrationResult registrationResult,
      RegistrationFinishRequest finishRequest) {
    byte[] newRecoveryToken = new byte[16];
    this.random.nextBytes(newRecoveryToken);

    RegistrationStartResponse startResponse = pending.startResponse();
    UserIdentity userIdentity = startResponse.getPublicKeyCredentialCreationOptions()
        .getUser();

    Long userId = pending.userId();
    if (startResponse.getMode() == Mode.NEW) {
      var insertedUser = this.dsl
          .insertInto(APP_USER, APP_USER.USERNAME, APP_USER.RECOVERY_TOKEN)
          .values(userIdentity.getName(), newRecoveryToken).returning(APP_USER.ID)
          .fetchOne();
      if (insertedUser == null) {
        throw new IllegalStateException("Failed to create user");
      }
      userId = insertedUser.getId();
    }
    else {
      int updated = this.dsl.update(APP_USER)
          .set(APP_USER.RECOVERY_TOKEN, newRecoveryToken)
          .where(APP_USER.ID.eq(userId)
              .and(APP_USER.RECOVERY_TOKEN.eq(pending.recoveryToken().getBytes())))
          .execute();
      if (updated != 1) {
        return null;
      }
      this.dsl.deleteFrom(CREDENTIALS).where(CREDENTIALS.APP_USER_ID.eq(userId))
          .execute();
    }

    String transports = registrationResult.getKeyId().getTransports()
        .map(values -> values.stream().map(transport -> transport.getId())
            .collect(Collectors.joining(",")))
        .filter(value -> !value.isEmpty()).orElse(null);

    this.credentialRepository.addCredential(userId, userIdentity.getId().getBytes(),
        registrationResult.getKeyId().getId().getBytes(),
        registrationResult.getPublicKeyCose().getBytes(), transports,
        finishRequest.getCredential().getResponse().getParsedAuthenticatorData()
            .getSignatureCounter());

    return Base58.encode(newRecoveryToken);
  }

  private String newRequestId() {
    byte[] requestId = new byte[16];
    this.random.nextBytes(requestId);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(requestId);
  }

  private record PendingRegistration(RegistrationStartResponse startResponse,
      Long userId, ByteArray recoveryToken) {
  }

}
