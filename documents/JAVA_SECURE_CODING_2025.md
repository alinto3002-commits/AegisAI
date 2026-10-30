# Java Enterprise Secure Coding Master Guide (2025 Edition)

[![OWASP Top 10](https://img.shields.io/badge/Security-OWASP%20Top%2010%20(2025)-red.svg)](https://owasp.org/Top10/)
[![Java SE](https://img.shields.io/badge/Java-17%20%7C%2021%20LTS-orange.svg)](https://docs.oracle.com/en/java/)
[![Spring Boot](https://img.shields.io/badge/Framework-Spring%20Boot%203.x-green.svg)](https://spring.io/projects/spring-boot)
[![SEI CERT](https://img.shields.io/badge/Standard-SEI%20CERT%20Java-blue.svg)](https://wiki.sei.cmu.edu/confluence/display/java/SEI+CERT+Oracle+Coding+Standard+for+Java)

This document represents the authoritative, enterprise-grade secure coding standard for Java applications, microservices, and Spring Boot / Jakarta EE systems. It incorporates the complete **OWASP Top 10 (2025 Edition)** taxonomy, the **CWE Top 25 Most Dangerous Software Weaknesses**, and the **SEI CERT Oracle Coding Standard for Java**.

---

## Table of Contents
1. [Core Defensive Principles & Java Runtime Security](#1-core-defensive-principles--java-runtime-security)
2. [OWASP Top 10 (2025) Java Threat Defenses & Code Patterns](#2-owasp-top-10-2025-java-threat-defenses--code-patterns)
   - [A01:2025 — Broken Access Control (CWE-22, CWE-862, CWE-639, CWE-918)](#a012025--broken-access-control-in-java)
   - [A02:2025 — Security Misconfiguration (CWE-16, CWE-942, CWE-215)](#a022025--security-misconfiguration-in-java)
   - [A03:2025 — Software Supply Chain Failures (CWE-1104, CWE-1395)](#a032025--software-supply-chain-failures-in-java)
   - [A04:2025 — Cryptographic Failures (CWE-327, CWE-328, CWE-329, CWE-338)](#a042025--cryptographic-failures-in-java)
   - [A05:2025 — Injection (CWE-89, CWE-78, CWE-611, CWE-90)](#a052025--injection-in-java-sql-command-xxe-ldap)
   - [A06:2025 — Insecure Design (CWE-1059, CWE-307)](#a062025--insecure-design-in-java)
   - [A07:2025 — Authentication Failures (CWE-798, CWE-347, CWE-287)](#a072025--authentication-failures-in-java)
   - [A08:2025 — Software or Data Integrity Failures (CWE-502, CWE-94)](#a082025--software-or-data-integrity-failures-in-java)
   - [A09:2025 — Security Logging and Alerting Failures (CWE-532, CWE-117)](#a092025--security-logging-and-alerting-failures-in-java)
   - [A10:2025 — Mishandling of Exceptional Conditions (CWE-755, CWE-390)](#a102025--mishandling-of-exceptional-conditions-in-java)
3. [Spring Boot 3.x & Jakarta EE Security Configuration](#3-spring-boot-3x--jakarta-ee-security-configuration)
4. [SEI CERT Java Rule Mappings (Top 15 Compliance Rules)](#4-sei-cert-java-rule-mappings)
5. [Automated Verification & CI/CD Security Gates](#5-automated-verification--cicd-security-gates)

---

## 1. Core Defensive Principles & Java Runtime Security

Enterprise Java applications must adhere to the following foundational engineering mandates:

- **Defense in Depth**: Implement multi-layered authorization checks. Do not rely solely on Spring Security API gateway route matching; enforce method-level security with `@PreAuthorize` on service and repository layers.
- **Fail Closed**: In any unexpected state, authorization check failure, or database error, terminate execution and deny access.
- **Data Immortality & Type Safety**: Leverage Java records, immutable data transfer objects (DTOs), and defensive copying for mutable state (`Collections.unmodifiableList`, `Arrays.copyOf`).
- **Zero Raw Object Serialization**: Never serialize or deserialize raw Java objects across trust boundaries with native `ObjectInputStream`. Standardize on JSON/Protobuf with strict schema enforcement.
- **Cryptographic Agility**: Configure algorithms through abstraction layers (JCA/JCE providers) using modern primitives (AES-256-GCM, Argon2id, Ed25519) rather than deprecated legacy defaults.

---

## 2. OWASP Top 10 (2025) Java Threat Defenses & Code Patterns

### A01:2025 — Broken Access Control in Java
**CWE Mappings:** `CWE-22` (Path Traversal), `CWE-862` (Missing Authorization), `CWE-639` (IDOR), `CWE-918` (SSRF)

#### Pattern 1: Insecure Direct Object Reference (IDOR) in Spring Controllers
Vulnerable applications expose database IDs directly in path parameters without verifying that the authenticated user owns the referenced resource.

```java
// ❌ VULNERABLE: Any authenticated user can read any invoice by altering {id}
@RestController
@RequestMapping("/api/invoices")
public class InvoiceController {
    @Autowired
    private InvoiceRepository invoiceRepository;

    @GetMapping("/{id}")
    public Invoice getInvoice(@PathVariable Long id) {
        return invoiceRepository.findById(id)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }
}
```

```java
// ✅ SECURE: Method-level authorization with ownership verification
@RestController
@RequestMapping("/api/invoices")
public class InvoiceController {
    @Autowired
    private InvoiceService invoiceService;

    @GetMapping("/{id}")
    @PreAuthorize("@invoiceSecurity.isOwner(#id, authentication) or hasRole('FINANCE_ADMIN')")
    public InvoiceDTO getInvoice(@PathVariable Long id) {
        return invoiceService.getInvoiceById(id);
    }
}
```

#### Pattern 2: Path Traversal & ZipSlip in Java File Operations
When accepting filenames from user uploads or zip archives, untrusted input containing `../` sequences can overwrite arbitrary system files.

```java
// ❌ VULNERABLE: Direct concatenation allows path traversal
File file = new File("/var/storage/uploads", userSuppliedFilename);
FileInputStream fis = new FileInputStream(file);
```

```java
// ✅ SECURE: Canonical path verification and boundary check
Path baseDir = Paths.get("/var/storage/uploads").toRealPath();
Path resolvedPath = baseDir.resolve(userSuppliedFilename).normalize();

if (!resolvedPath.startsWith(baseDir) || !Files.exists(resolvedPath)) {
    throw new SecurityException("Unauthorized file path access attempt: " + userSuppliedFilename);
}
byte[] content = Files.readAllBytes(resolvedPath);
```

#### Pattern 3: Server-Side Request Forgery (SSRF) via Java HTTP Clients
Accepting arbitrary URLs from users and fetching remote content without egress filtering allows attackers to access internal cloud metadata (`169.254.169.254`) or intranet microservices.

```java
// ❌ VULNERABLE: Unvalidated HTTP request to arbitrary URL
URL url = new URL(userProvidedUrl);
InputStream in = url.openStream();
```

```java
// ✅ SECURE: Domain allowlisting and private IP egress blocking
URI targetUri = URI.create(userProvidedUrl);
InetAddress address = InetAddress.getByName(targetUri.getHost());

if (address.isLoopbackAddress() || address.isSiteLocalAddress() || address.isLinkLocalAddress()) {
    throw new SecurityException("SSRF blocked: Destination resolves to internal network address.");
}

HttpClient client = HttpClient.newBuilder()
    .connectTimeout(Duration.ofSeconds(3))
    .build();
HttpRequest request = HttpRequest.newBuilder().uri(targetUri).GET().build();
HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
```

---

### A02:2025 — Security Misconfiguration in Java
**CWE Mappings:** `CWE-16` (Misconfiguration), `CWE-942` (Overly Permissive CORS), `CWE-215` (Exposed Debug/Stack Traces)

#### Pattern 1: Wildcard CORS and Disabled CSRF
Configuring Spring Security with `origins = "*"` while enabling credentials permits malicious websites to hijack authenticated user sessions.

```java
// ❌ VULNERABLE: Permissive CORS and disabled CSRF in session-based app
@Configuration
@EnableWebSecurity
public class InsecureSecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(request -> {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(List.of("*"));
                config.setAllowCredentials(true);
                return config;
            }));
        return http.build();
    }
}
```

```java
// ✅ SECURE: Explicit CORS origins, CSRF token cookies, and hardened security headers
@Configuration
@EnableWebSecurity
public class SecureSecurityConfig {
    @Value("${app.security.allowed-origins}")
    private List<String> allowedOrigins;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .cors(cors -> cors.configurationSource(request -> {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(allowedOrigins);
                config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
                config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-XSRF-TOKEN"));
                config.setAllowCredentials(true);
                return config;
            }))
            .headers(headers -> headers
                .contentTypeOptions(Customizer.withDefaults())
                .frameOptions(frame -> frame.deny())
                .xssProtection(Customizer.withDefaults()));
        return http.build();
    }
}
```

---

### A03:2025 — Software Supply Chain Failures in Java
**CWE Mappings:** `CWE-1104` (Unmaintained Third-Party Components), `CWE-1395` (Vulnerable Dependencies)

#### Pattern: Automated Maven Dependency-Check and SBOM Enforcement
Java projects must audit all direct and transitive dependencies against the National Vulnerability Database (NVD) during every CI build.

```xml
<!-- ✅ SECURE: Enforce OWASP Dependency-Check in pom.xml -->
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>9.0.9</version>
    <configuration>
        <failBuildOnCVSS>7.0</failBuildOnCVSS>
        <assemblyAnalyzerEnabled>false</assemblyAnalyzerEnabled>
    </configuration>
    <executions>
        <execution>
            <goals><goal>check</goal></goals>
        </execution>
    </executions>
</plugin>
```

---

### A04:2025 — Cryptographic Failures in Java
**CWE Mappings:** `CWE-327` (Broken Crypto), `CWE-328` (Reversible/Weak Hash), `CWE-329` (Predictable IV), `CWE-338` (Weak PRNG)

#### Pattern 1: Weak Password Hashing with MD5 / SHA-256
Fast hashing algorithms without memory hardness or salts allow dictionary and GPU-based rainbow table cracking.

```java
// ❌ VULNERABLE: MD5 or plain SHA-256 for passwords
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
```

```java
// ✅ SECURE: Argon2id or BCrypt with high computational work factor
@Bean
public PasswordEncoder passwordEncoder() {
    // Argon2PasswordEncoder(saltLength, hashLength, parallelism, memoryInKb, iterations)
    return new Argon2PasswordEncoder(16, 32, 1, 65536, 4);
    // Alternatively: return new BCryptPasswordEncoder(12);
}
```

#### Pattern 2: AES Symmetric Encryption with ECB Mode
Electronic Codebook (ECB) mode encrypts identical plaintext blocks into identical ciphertext blocks, preserving visual and structural patterns of sensitive data.

```java
// ❌ VULNERABLE: AES in ECB mode without IV or integrity tag
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey);
```

```java
// ✅ SECURE: AES-256-GCM with authenticated data and unique 96-bit nonce
byte[] iv = new byte[12];
SecureRandom.getInstanceStrong().nextBytes(iv);

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec spec = new GCMParameterSpec(128, iv); // 128-bit auth tag
cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
byte[] cipherText = cipher.doFinal(plainText);
```

#### Pattern 3: Insecure Random Number Generation and Cryptographic Randomness with SecureRandom (CWE-338)
java.util.Random utilizes a linear congruential formula that is deterministic and easily predictable from previous outputs. For security-sensitive tokens, password reset links, session identifiers, and cryptographic keys, use java.security.SecureRandom.

```java
// ❌ VULNERABLE: java.util.Random used for security-sensitive tokens or keys
Random random = new Random();
String resetToken = Long.toHexString(random.nextLong());
```

```java
// ✅ SECURE: Cryptographically strong pseudo-random number generation with SecureRandom
SecureRandom secureRandom = SecureRandom.getInstanceStrong();
byte[] tokenBytes = new byte[32];
secureRandom.nextBytes(tokenBytes);
String resetToken = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
```


---

### A05:2025 — Injection in Java (SQL, Command, XXE, LDAP)
**CWE Mappings:** `CWE-89` (SQL Injection), `CWE-78` (OS Command Injection), `CWE-611` (XXE), `CWE-90` (LDAP Injection)

#### Pattern 1: SQL Injection in Raw JDBC & Hibernate JPQL
Concatenating untrusted strings into query text allows arbitrary database manipulation or data exfiltration.

```java
// ❌ VULNERABLE: Concatenation in JDBC Statement
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");

// ❌ VULNERABLE: Concatenation in Hibernate EntityManager
Query query = entityManager.createQuery("FROM Account a WHERE a.owner = '" + ownerName + "'");
```

```java
// ✅ SECURE: Parameterized PreparedStatement in JDBC
String sql = "SELECT * FROM users WHERE username = ? AND is_active = ?";
try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
    pstmt.setString(1, username);
    pstmt.setBoolean(2, true);
    try (ResultSet rs = pstmt.executeQuery()) {
        // Process results safely
    }
}

// ✅ SECURE: Named parameter binding in JPA / Hibernate
TypedQuery<Account> query = entityManager.createQuery(
    "FROM Account a WHERE a.owner = :ownerName", Account.class);
query.setParameter("ownerName", ownerName);
List<Account> accounts = query.getResultList();
```

#### Pattern 2: OS Command Injection via Runtime.exec
Invoking system command shells (`cmd.exe /c` or `sh -c`) with user input allows command chaining (`&&`, `|`, `;`).

```java
// ❌ VULNERABLE: Shell command execution with concatenation
Runtime.getRuntime().exec("sh -c ping -c 1 " + targetHost);
```

```java
// ✅ SECURE: ProcessBuilder with strict argument array and input validation
if (!targetHost.matches("^[a-zA-Z0-9.-]+$")) {
    throw new IllegalArgumentException("Invalid hostname format");
}
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", targetHost);
pb.redirectErrorStream(true);
Process process = pb.start();
int exitCode = process.waitFor();
```

#### Pattern 3: XML External Entity (XXE) Injection
Default XML parsers resolve external entity references, allowing attackers to read server files (`/etc/passwd`) or trigger internal SSRF.

```java
// ❌ VULNERABLE: Default DocumentBuilderFactory resolves external DTDs
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
Document doc = dbf.newDocumentBuilder().parse(userXmlInputStream);
```

```java
// ✅ SECURE: Completely disable DTDs and external entity expansion
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
Document doc = dbf.newDocumentBuilder().parse(userXmlInputStream);
```

---

### A06:2025 — Insecure Design in Java
**CWE Mappings:** `CWE-1059` (Insecure Design), `CWE-307` (Missing Rate Limiting)

#### Pattern: Distributed Rate Limiting with Bucket4j & Redis
Protect authentication and resource-intensive endpoints from brute force and denial of service.

```java
// ✅ SECURE: Bucket4j rate limiting filter
@Component
public class LoginRateLimiterFilter extends OncePerRequestFilter {
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    private Bucket createNewBucket() {
        Bandwidth limit = Bandwidth.classic(5, Refill.intervally(5, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if ("/api/auth/login".equals(request.getRequestURI())) {
            String clientIp = request.getRemoteAddr();
            Bucket bucket = buckets.computeIfAbsent(clientIp, k -> createNewBucket());
            if (!bucket.tryConsume(1)) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.getWriter().write("{\"error\": \"Rate limit exceeded. Try again in 1 minute.\"}");
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
```

---

### A07:2025 — Authentication Failures in Java
**CWE Mappings:** `CWE-798` (Hardcoded Secrets), `CWE-347` (Improper JWT Signature Verification)

#### Pattern 1: Hardcoded Secrets in Java Code
Embedding passwords, private keys, or API tokens directly in `.java` source code leaks credentials into git repositories.

```java
// ❌ VULNERABLE: Hardcoded JWT secret
public class TokenService {
    private static final String SECRET_KEY = "my_super_secret_jwt_key_that_should_never_be_here";
}
```

```java
// ✅ SECURE: Injected via Spring Environment or Cloud Vault
@Service
public class TokenService {
    @Value("${app.security.jwt.secret}")
    private String jwtSecret;
}
```

#### Pattern 2: Flawed JWT Verification & Algorithm Confused Attacks
Parsing JWTs without validating the signing algorithm allows attackers to forge tokens using `alg: "none"` or public HMAC key substitution.

```java
// ❌ VULNERABLE: Parsing without explicit key and algorithm enforcement
Claims claims = Jwts.parser().parseClaimsJwt(token).getBody();
```

```java
// ✅ SECURE: Enforce HMAC-SHA256 signature and verify expiration
SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
Claims claims = Jwts.parserBuilder()
    .setSigningKey(key)
    .build()
    .parseClaimsJws(token)
    .getBody();
```

---

### A08:2025 — Software or Data Integrity Failures in Java
**CWE Mappings:** `CWE-502` (Deserialization of Untrusted Data), `CWE-94` (Code Injection)

#### Pattern: Insecure Java Deserialization
Calling `readObject()` on data from network sockets allows gadget chains in common libraries (e.g., Apache Commons Collections) to trigger arbitrary Remote Code Execution (RCE).

```java
// ❌ VULNERABLE: Deserializing raw Java object from untrusted stream
ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
UserSession session = (UserSession) ois.readObject();
```

```java
// ✅ SECURE (Approach A): Migrate to JSON with strict schema validation
ObjectMapper mapper = JsonMapper.builder().deactivateDefaultTyping().build();
UserSessionDTO session = mapper.readValue(socket.getInputStream(), UserSessionDTO.class);

// ✅ SECURE (Approach B): If ObjectInputStream is required, enforce ObjectInputFilter (Java 9+)
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.mycompany.dto.UserSession;!*" // Whitelist UserSession only, reject all other classes
);
ois.setObjectInputFilter(filter);
```

---

### A09:2025 — Security Logging and Alerting Failures in Java
**CWE Mappings:** `CWE-532` (Sensitive Information in Logs), `CWE-117` (Log Injection / CRLF)

#### Pattern: Sensitive Data Masking & CRLF Injection Prevention
Logging user credentials, tokens, or unescaped newline characters allows attackers to inject fake log entries or compromise compliance (PCI-DSS / HIPAA).

```java
// ❌ VULNERABLE: Logging raw credentials and unescaped input
logger.info("Login attempt for user: " + username + " with password: " + password);
```

```java
// ✅ SECURE: Strip newlines and never log sensitive fields
String safeUsername = username.replaceAll("[\r\n]", "_");
logger.warn("Authentication failed for username: {}", safeUsername);
```

---

### A10:2025 — Mishandling of Exceptional Conditions in Java
**CWE Mappings:** `CWE-755` (Improper Handling of Exceptional Conditions), `CWE-390` (Silent Error Swallowing)

#### Pattern: Empty Catch Blocks & Catching Throwable
Silently ignoring exceptions masks security failures, resource leaks, and database deadlocks.

```java
// ❌ VULNERABLE: Silently suppressing all exceptions
try {
    processOrderPayment(orderId, paymentToken);
} catch (Exception e) {
    // empty block - failure is hidden!
}
```

```java
// ✅ SECURE: Specific exception handling, transaction rollback, and structured error reporting
try {
    processOrderPayment(orderId, paymentToken);
} catch (PaymentGatewayException | InsufficientFundsException e) {
    logger.error("Payment failed for orderId={}: {}", orderId, e.getMessage(), e);
    transactionManager.rollback(status);
    throw new BusinessServiceException("Payment processing failed", e);
} finally {
    releaseLock(orderId);
}
```

#### Pattern 2: Declaring Generic throws Exception in Method Signatures
Declaring 'throws Exception' in method signatures breaks exception abstraction, forces callers to catch generic java.lang.Exception, and masks specific failure modes (CWE-398). Methods should declare the specific checked exception types thrown by the operations they perform or wrap them in descriptive unchecked domain exceptions.

```java
// ❌ VULNERABLE / CODE SMELL: Generic throws Exception in signature
public byte[] encryptPayload(String data) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key, spec);
    return cipher.doFinal(data.getBytes());
}
```

```java
// ✅ SECURE: Specific checked exceptions declared based on operations
public byte[] encryptPayload(String data) throws GeneralSecurityException {
    try {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(data.getBytes());
    } catch (GeneralSecurityException e) {
        logger.error("Encryption failed", e);
        throw e;
    }
}
```


---

## 3. Spring Boot 3.x & Jakarta EE Security Configuration

```properties
# application.properties Security Hardening Standard
server.error.include-stacktrace=never
server.error.include-message=never
server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.secure=true
server.servlet.session.cookie.same-site=strict
spring.jpa.show-sql=false
management.endpoints.web.exposure.include=health,info,metrics
management.endpoint.health.show-details=when-authorized
```

---

## 4. SEI CERT Java Rule Mappings

| CERT Rule | Standard Title | Enforcement Strategy |
| :--- | :--- | :--- |
| **IDS00-J** | Prevent SQL Injection | Parameterize all JDBC `PreparedStatement` and JPA queries. |
| **IDS01-J** | Normalize strings before validation | Invoke `Normalizer.normalize()` prior to regex or security checks. |
| **FIO16-J** | Canonicalize path names before verification | Call `Path.toRealPath()` and verify root containment. |
| **SEC01-J** | Do not grant excessive privileges | Execute application under non-root service account. |
| **SER00-J** | Enable serialization filters | Apply `ObjectInputFilter` on all `ObjectInputStream` instances. |
| **ERR00-J** | Do not suppress or ignore exceptions | Log diagnostic context via SLF4J and fail closed. |
| **MSC02-J** | Generate strong random numbers | Use `SecureRandom.getInstanceStrong()` for cryptography. |

---

## 5. Automated Verification & CI/CD Security Gates

- **Quality Score Minimum**: 80/100
- **Zero Critical / High Findings**: Any `CRITICAL` or `HIGH` OWASP finding halts the merge pipeline.
- **Dependency Audit**: `mvn dependency-check:check` must pass with 0 CVSS >= 7.0 issues.

---

## 6. Enterprise Spring Security 6 Configuration Patterns

Modern Spring Security 6 (Spring Boot 3.x) relies entirely on lambda-based declarative configuration:

### 6.1 Stateless OAuth2 Resource Server with JWT Validation
```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class OAuth2ResourceServerConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable) // Disabled strictly because API is stateless JWT-based
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**", "/actuator/health").permitAll()
                .requestMatchers("/api/admin/**").hasRole("SYSTEM_ADMIN")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            )
            .headers(headers -> headers
                .contentTypeOptions(Customizer.withDefaults())
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'; frame-ancestors 'none';"))
            );
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(this.jwkSetUri).build();
        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(
            new JwtTimestampValidator(Duration.ofSeconds(30)),
            new JwtIssuerValidator("https://auth.company.com")
        );
        jwtDecoder.setJwtValidator(validator);
        return jwtDecoder;
    }

    private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthorityPrefix("ROLE_");
        authoritiesConverter.setAuthoritiesClaimName("roles");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }
}
```

### 6.2 Custom PermissionEvaluator for Fine-Grained ABAC
```java
@Component
public class TenantPermissionEvaluator implements PermissionEvaluator {

    @Override
    public boolean hasPermission(Authentication auth, Object targetDomainObject, Object permission) {
        if (auth == null || targetDomainObject == null || !(permission instanceof String)) {
            return false;
        }
        String targetType = targetDomainObject.getClass().getSimpleName().toUpperCase();
        return hasPrivilege(auth, targetType, permission.toString().toUpperCase());
    }

    @Override
    public boolean hasPermission(Authentication auth, Serializable targetId, String targetType, Object permission) {
        // Enforce tenant boundary: user organization must match target resource organization
        CustomUserPrincipal principal = (CustomUserPrincipal) auth.getPrincipal();
        return principal.isTenantAuthorized(targetId, targetType);
    }

    private boolean hasPrivilege(Authentication auth, String targetType, String permission) {
        return auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("PERMISSION_" + targetType + "_" + permission));
    }
}
```

---

## 7. Hibernate / JPA Secure Data Access Patterns

### 7.1 Dynamic Sorting SQL Injection Mitigation
Directly passing user strings into `Sort.by(userInput)` allows SQL injection in Hibernate `ORDER BY` clauses (`CWE-89`).

```java
// ❌ VULNERABLE: Direct user input into Sort.by()
@GetMapping("/users")
public List<UserDTO> getUsers(@RequestParam String sortBy) {
    Sort sort = Sort.by(sortBy); // If sortBy = "(CASE WHEN (1=1) THEN id ELSE name END)", SQLi occurs!
    return userRepository.findAll(sort).stream().map(userMapper::toDto).toList();
}

// ✅ SECURE: Whitelist validated sort properties
private static final Set<String> ALLOWED_SORT_FIELDS = Set.of("id", "username", "createdAt", "email");

@GetMapping("/users")
public List<UserDTO> getUsers(@RequestParam(defaultValue = "createdAt") String sortBy,
                              @RequestParam(defaultValue = "DESC") Sort.Direction direction) {
    if (!ALLOWED_SORT_FIELDS.contains(sortBy)) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid sort field: " + sortBy);
    }
    Sort sort = Sort.by(direction, sortBy);
    return userRepository.findAll(sort).stream().map(userMapper::toDto).toList();
}
```

### 7.2 Secure JPA Criteria API with Type-Safe Specifications
```java
public class UserSpecifications {
    public static Specification<User> hasTenantAndStatus(Long tenantId, UserStatus status) {
        return (root, query, cb) -> cb.and(
            cb.equal(root.get("tenant").get("id"), tenantId),
            cb.equal(root.get("status"), status)
        );
    }
}
```

---

## 8. Java Microservices mTLS & Inter-Service Security

### 8.1 Mutual TLS (mTLS) with Apache HttpClient
```java
@Configuration
public class MutualTlsClientConfig {

    @Bean
    public HttpClient secureHttpClient(
            @Value("${mtls.keystore.path}") Resource keyStoreResource,
            @Value("${mtls.keystore.password}") String keyStorePassword,
            @Value("${mtls.truststore.path}") Resource trustStoreResource,
            @Value("${mtls.truststore.password}") String trustStorePassword) throws Exception {

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(keyStoreResource.getInputStream(), keyStorePassword.toCharArray());

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(trustStoreResource.getInputStream(), trustStorePassword.toCharArray());

        SSLContext sslContext = SSLContextBuilder.create()
            .loadKeyMaterial(keyStore, keyStorePassword.toCharArray())
            .loadTrustMaterial(trustStore, new TrustSelfSignedStrategy())
            .build();

        return HttpClients.custom()
            .setSSLContext(sslContext)
            .build();
    }
}
```

---

## 9. Automated JUnit 5 Security Test Suite Recipes

Writing automated tests to verify security controls prevents regressions during refactoring:

### 9.1 IDOR Access Control Verification Test
```java
@SpringBootTest
@AutoConfigureMockMvc
public class InvoiceSecurityTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(username = "attacker", roles = {"USER"})
    public void testCannotAccessOtherUserInvoice() throws Exception {
        // Given invoice #99 belongs to user "victim", user "attacker" must receive HTTP 403 Forbidden
        mockMvc.perform(get("/api/invoices/99")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"FINANCE_ADMIN"})
    public void testAdminCanAccessAnyInvoice() throws Exception {
        mockMvc.perform(get("/api/invoices/99")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }
}
```

### 9.2 SQL Injection Payload Rejection Test
```java
@SpringBootTest
public class SqlInjectionDefenseTest {

    @Autowired
    private UserRepository userRepository;

    @Test
    public void testSqlInjectionPayloadIsTreatedAsLiteralValue() {
        String maliciousUsername = "admin' OR '1'='1";
        // PreparedStatement treats the payload strictly as literal data; returns empty optional safely
        Optional<User> user = userRepository.findByUsername(maliciousUsername);
        assertTrue(user.isEmpty(), "SQL Injection payload must not return records");
    }
}
```
