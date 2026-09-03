export function isPasskeySupported(): boolean {
  return (
    typeof window.PublicKeyCredential === 'function' &&
    typeof navigator.credentials?.get === 'function' &&
    typeof navigator.credentials?.create === 'function' &&
    typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function' &&
    typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function'
  );
}

export function isExpectedCredentialError(error: unknown): boolean {
  return (
    error instanceof DOMException &&
    (error.name === 'AbortError' || error.name === 'NotAllowedError')
  );
}
