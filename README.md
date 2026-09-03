# WebAuthn demo

A small passkey-only application with an Angular client, Spring Boot API, Yubico's
WebAuthn server library, jOOQ, Flyway, and PostgreSQL. Users can create an account,
sign in with a discoverable passkey, and replace a lost passkey with a one-time
recovery code.

The project originated as the companion code for
[this WebAuthn article](https://blog.rasc.ch/2019/08/webauthn.html).

This is demonstration code, not a complete identity product. In particular, the
in-progress WebAuthn ceremonies are kept in one server process, so production
deployments with multiple instances need a shared, one-time challenge store.

## Prerequisites

- Java 25
- Node.js and npm
- Docker with Docker Compose
- Optional: [Task](https://taskfile.dev/) for the shortcuts in `Taskfile.yml`

WebAuthn requires a secure context. Browsers treat `localhost` as secure for local
development; use HTTPS everywhere else.

## Run locally

Start PostgreSQL:

```shell
docker compose -f server/docker-compose.yml up -d
```

In one terminal, start the API:

```shell
cd server
./mvnw spring-boot:run
```

On Windows, use `mvnw.cmd` instead of `./mvnw`.

In another terminal, start the client:

```shell
cd client
npm install
npm start
```

Open <http://localhost:4200>. The database is stored in the named Docker volume
`server_wa_data`, so `docker compose down` does not erase registered accounts.
Use `docker compose -f server/docker-compose.yml down -v` only when you explicitly
want to delete that data.

The recovery code is displayed once after registration. Saving it is the only way
to replace a passkey when every registered authenticator is unavailable. Recovery
invalidates the previous passkey and rotates the recovery code.

## Verify and package

Run all configured checks:

```shell
task verify
```

Or run them directly:

```shell
cd client
npm run lint
npm run build

cd ../server
./mvnw test
```

`task build` builds the Angular client first and then packages it into
`server/target/webauthn-demo.jar`. Run the packaged application with:

```shell
java -jar server/target/webauthn-demo.jar
```

## Configuration

The local defaults live in `server/src/main/resources/application.properties`.
Override them through standard Spring Boot configuration (environment variables,
command-line arguments, or an external properties file). Production deployments
must set at least:

- `app.relying-party-id` to the site's effective domain
- `app.relying-party-origins` to the exact HTTPS origin or origins
- the `spring.datasource.*` settings for PostgreSQL
- secure session-cookie settings appropriate for the TLS deployment

The relying-party ID and allowed origins must match the site where the browser
executes the WebAuthn ceremony.

## API flow

Registration and authentication both use two calls: a `start` call creates a
short-lived challenge and a `finish` call consumes it. Challenge identifiers are
single-use and expire after five minutes. Account creation and recovery updates
are transactional; a canceled new registration does not reserve its username.
Unsafe API calls are protected with Spring Security's SPA-oriented CSRF support;
Angular obtains the token during application startup and sends it automatically.

The application intentionally uses usernameless authentication, so passkeys can
appear through browser autofill in the login username field.
