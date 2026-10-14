# Session authentication

Requires Java 21 and MySQL. Check the database connection in
`src/main/resources/application.properties`. Redis is not required; sessions use
the servlet container and are lost when the application restarts.
Run `./mvnw spring-boot:run` (Windows: `.\mvnw.cmd spring-boot:run`).
The application listens on port 8081.

Users are loaded from the existing User entity using UserRepository. Store passwords
as BCrypt hashes created with the configured PasswordEncoder, never as plaintext.
Roles are stored as `Admin` or `User` and exposed as `ROLE_ADMIN` or `ROLE_USER`.
There is no public registration endpoint or default account. Insert users through
your trusted database provisioning process. Existing ordinal role columns must be
migrated to enum names before using this version.

## API flow

1. GET `/auth/csrf`. Keep the session cookie and read `headerName` and `token` from
   the JSON response.
2. POST `/auth/login` (or `/auth`) with JSON
   `{"username":"alice","password":"your-password"}` and the CSRF token in the
   returned header (normally `X-CSRF-TOKEN`). Keep the updated session cookie.
3. GET `/auth/me` with the cookie to get the username and authorities. All other
   application endpoints require authentication. Missing authentication returns 401.
4. Fetch `/auth/csrf` again after login because authentication rotates the token.
   Send this token and the cookie for subsequent POST/PUT/PATCH/DELETE requests.
5. POST `/auth/logout` with the token and cookie. Returns 204 and invalidates the
   session. Later protected requests return 401.

Clients must
retain cookies (browser fetch: `credentials: 'include'`). This configuration assumes
a same-origin frontend. Set `server.servlet.session.cookie.secure=true` for HTTPS.
Hibernate schema update is enabled for local development; use reviewed migrations
and schema validation in production.
