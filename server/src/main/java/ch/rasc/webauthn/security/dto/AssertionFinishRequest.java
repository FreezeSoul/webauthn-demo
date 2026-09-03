package ch.rasc.webauthn.security.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class AssertionFinishRequest {

  @NotBlank
  private final String assertionId;

  @NotNull
  private final PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential;

  @JsonCreator
  public AssertionFinishRequest(@JsonProperty("assertionId") String assertionId,
      @JsonProperty("credential") PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential) {
    this.assertionId = assertionId;
    this.credential = credential;
  }

  public String getAssertionId() {
    return this.assertionId;
  }

  public PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> getCredential() {
    return this.credential;
  }

}
