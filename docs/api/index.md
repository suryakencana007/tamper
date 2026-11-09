# API reference

Every exported package, and the names it offers. This is deliberately a **list, not a copy** of
the Go documentation: the comment on a type is the thing that must not be duplicated, because a
second copy is a second thing to forget — the lesson this repository learned on its changelog.

Generated from `go doc -short` and checked by a test, so a renamed symbol fails CI instead of
quietly disappearing from a page nobody re-reads.

::: tip Which version are you reading?
This site documents the **current release**, and the version it documents is named in the header
of every page. There is no per-version site, and that is a decision rather than an omission — see
[Versioning](#versioning) below.


## `tenant`

The tenancy vocabulary: `tenant.ID` (zero value denies, `tenant.Single` says single-tenant on purpose), descriptors, entitlements and the parentage walk.

```text
var ErrConflict = errors.New("tenant: tenant already exists") ...
var ErrDomainNotNormalised = errors.New("tenant: domain is not normalised") ...
var ErrHierarchyCycle = errors.New("tenant: hierarchy cycle") ...
var ErrNotFound = errors.New("tenant: not found") ...
var ErrVerificationFailed = errors.New("tenant: domain verification failed")
var Single = ID{ ... }
func FromContext(ctx context.Context) (string, bool)
func Inherited[T any](ctx context.Context, s Store, allow Inheritance, id ID, own InheritFunc[T]) ([]T, error)
func IsProperSubdomain(child, parent string) bool
func IsPublicEmailDomain(domain string) bool
func NewVerificationToken() string
func RequireNormalisedDomain(domain string) error
func WithTenant(ctx context.Context, id string) context.Context
type AdminStore interface{ ... }
type DNSVerifier interface{ ... }
func NewDNSVerifier(opts ...DNSVerifierOption) DNSVerifier
type DNSVerifierOption func(*dnsVerifier)
func WithTXTLookup(fn func(ctx context.Context, name string) ([]string, error)) DNSVerifierOption
func WithTXTRecordPrefix(prefix string) DNSVerifierOption
type Descriptor struct{ ... }
type DomainAuthority struct{ ... }
func InheritedDomainAuthority(ctx context.Context, s Store, domains DomainStore, tenantID ID, domain string) (DomainAuthority, error)
type DomainRecord struct{ ... }
func ResolveDomain(ctx context.Context, s DomainStore, emailDomain string) (DomainRecord, error)
type DomainStore interface{ ... }
type EntitlementStore interface{ ... }
func InheritingEntitlements(inner EntitlementStore, s Store) EntitlementStore
type Entitlements struct{ ... }
type ID struct{ ... }
func Ancestors(ctx context.Context, s Store, id ID) ([]ID, error)
func FromStored(s string) ID
func New(s string) ID
type InheritFunc[T any] func(ctx context.Context, id ID) ([]T, error)
type Inheritance func(ctx context.Context, id ID) (bool, error)
type MemStore struct{ ... }
func NewMemStore() *MemStore
type Resolver interface{ ... }
type Status string
const StatusActive Status = "active" ...
type Store interface{ ... }
```

Full documentation, including the prose comments: [`tenant` on pkg.go.dev](https://pkg.go.dev/github.com/suryakencana007/tamper/tenant).

## `authz`

The decision engine: one `Authorizer` interface over a rank `RBAC` or a set-based `PermissionSet`, with the reverse queries a console needs.

```text
const SuperuserKey = "*"
var ErrTenantRequired = errors.New("authz: tenant is required")
type Action string
type Authorizer interface{ ... }
type Binding struct{ ... }
type BindingStore interface{ ... }
type CheckRequest struct{ ... }
type Decision struct{ ... }
type Hierarchy map[string][]Role
type MemPermissionStore struct{ ... }
func NewMemPermissionStore() *MemPermissionStore
type MemStore struct{ ... }
func NewMemStore(bindings ...Binding) *MemStore
type PermissionSet struct{ ... }
func NewPermissionSet(store PermissionStore) (*PermissionSet, error)
type PermissionSetResult struct{ ... }
type PermissionStore interface{ ... }
func NewRBACPermissionStore(store BindingStore, h Hierarchy, p Policy) (PermissionStore, error)
type Policy map[Action][]Requirement
type RBAC struct{ ... }
func NewRBAC(store BindingStore, h Hierarchy, p Policy) (*RBAC, error)
type Requirement struct{ ... }
type Resource struct{ ... }
type Role string
type Subject struct{ ... }
```

Full documentation, including the prose comments: [`authz` on pkg.go.dev](https://pkg.go.dev/github.com/suryakencana007/tamper/authz).

## `identity`

Credentials and sessions: register, login, refresh, logout, TOTP enrolment, multi-IdP linking — and the ports that keep policy out of the library.

```text
const MinPasswordLen = 8 ...
const ThrottleStepTOTP = "totp" ...
const DefaultInvitationTTL = 7 * 24 * time.Hour
var ErrInvalidCredentials = errors.New("identity: invalid credentials") ...
func NormaliseEmail(raw string) (string, error)
type Core struct{ ... }
func New(store Store, jwt *crypto.JWTService, opts ...Option) (*Core, error)
type Hooks struct{ ... }
type Identity struct{ ... }
type ImpersonationPolicy interface{ ... }
type Invitation struct{ ... }
type InvitationStore interface{ ... }
type MemStore struct{ ... }
func NewMemStore() *MemStore
type MembershipStore interface{ ... }
type NewIdentity struct{ ... }
type NewUser struct{ ... }
type Option func(*Core)
func WithClock(now func() time.Time) Option
func WithDefaultACR(acr string) Option
func WithEnterTenantTTL(d time.Duration) Option
func WithHooks(h Hooks) Option
func WithIDGenerator(newID func() string) Option
func WithImpersonation(p ImpersonationPolicy, ttl time.Duration) Option
func WithInvitations(s InvitationStore) Option
func WithKeySet(keys *crypto.KeySet) Option
func WithMemberships(s MembershipStore) Option
func WithPasswordPolicy(p PasswordPolicy) Option
func WithRefreshTTL(d time.Duration) Option
func WithSecondFactorPolicy(p SecondFactorPolicy) Option
func WithTOTPRequired(required bool) Option
func WithThrottling(t Throttling) Option
type PasswordPolicy interface{ ... }
type PasswordPolicyFunc func(ctx context.Context, tenantID tenant.ID, userID, email, password string) error
type RefreshSession struct{ ... }
type SecondFactorPolicy interface{ ... }
type SecondFactorRequirement struct{ ... }
type Store interface{ ... }
type TOTPEnrollment struct{ ... }
type TOTPState struct{ ... }
type ThrottledError struct{ ... }
type Throttling struct{ ... }
type Tokens struct{ ... }
type User struct{ ... }
```

Full documentation, including the prose comments: [`identity` on pkg.go.dev](https://pkg.go.dev/github.com/suryakencana007/tamper/identity).

## `crypto`

Tokens, passwords and secrets: JWT issue/verify, bcrypt, refresh-token hashing, TOTP, the `acr`/`amr` claim vocabulary, and the KEK keyset that seals secrets at rest.

```text
const ACRLocalPassword = "urn:tamper:auth:local-password" ...
const AMRPassword = "pwd" ...
const RefreshTokenBytes = 32
const TOTPIssuer = "Barista"
const TOTPRecoveryCodeBytes = 6
const TOTPRecoveryCodeCount = 10
const TOTPSecretBytes = 20
var Cost = 12
var ErrEmptyKeySet = errors.New("auth: keyset must have at least one key")
var ErrEnteredTenants = errors.New(...)
var ErrInvalidPassword = errors.New("auth: invalid password")
var ErrInvalidRefreshToken = errors.New("auth: invalid refresh token")
var ErrInvalidTOTPCode = errors.New("auth: invalid totp code")
var ErrInvalidToken = errors.New("auth: invalid token")
var ErrKeyIDZero = errors.New("auth: keyset keyId 0 is reserved")
var ErrSecretBoxOpen = errors.New("auth: secretbox open failed")
var ErrSelfImpersonation = errors.New("auth: an impersonated token needs an actor different from the target")
var ErrTenantRequired = errors.New("auth: tenant id is required")
var ErrUnknownKeyID = errors.New("auth: keyset open: keyId not in keyset")
func GenerateTOTPRecoveryCodes() ([]string, error)
func GenerateTOTPSecret() (string, error)
func HashPassword(plain string) (string, error)
func HashRecoveryCodes(codes []string) ([]string, error)
func HashRefreshToken(token string) (string, error)
func MatchRecoveryCode(code string, hashes []string) (matched string, ok bool)
func NewRefreshToken() (string, error)
func OTPAuthURI(secretBase32, accountEmail string) string
func ResetStubHashForTesting()
func VerifyPassword(hash, plain string) error
func VerifyStub(plain string) error
func VerifyTOTPCode(secretBase32, code string) error
type AccessClaims struct{ ... }
type JWTConfig struct{ ... }
type JWTOption func(*JWTService)
func WithSigner(s Signer) JWTOption
func WithVerifiers(byKID map[string]Signer) JWTOption
type JWTService struct{ ... }
func NewJWTService(cfg JWTConfig, opts ...JWTOption) *JWTService
type JWTServiceTesting struct{ ... }
type KEKEntry struct{ ... }
type KeySet struct{ ... }
func NewKeySet(entries []KEKEntry, writeKeyID uint8) (*KeySet, error)
type SecretBox struct{ ... }
func NewSecretBox(kekHex string) (*SecretBox, error)
type Signer interface{ ... }
func NewHS256Signer(secret []byte) Signer
type Throttle interface{ ... }
func NewTokenBucket(rate int, per time.Duration, burst int) Throttle
```

Full documentation, including the prose comments: [`crypto` on pkg.go.dev](https://pkg.go.dev/github.com/suryakencana007/tamper/crypto).

## `audit`

The tamper-evident log: a hash chain with verification, per-tenant queries, and commitment-based redaction.

```text
const CanonicalVersion4 = 4
const CommitmentSize = sha256.Size
const CompletenessIssuerAttested = "issuer-attested"
const HashSize = sha256.Size
const RowSaltSize = 32
var ErrCommitmentMismatch = errors.New("audit: field commitment does not match stored value")
func ClusterIDFromContext(ctx context.Context) string
func ComputeHash(e Event, prevHash []byte) ([]byte, error)
func HashHex(h []byte) string
func InsertEventDirectForTest(ctx context.Context, l *SQLiteLogger, e Event) error
func IsChainMismatch(err error) bool
func IsRedacted(salt []byte) bool
func IsUniqueViolation(err error) bool
func NewRowSalt() ([]byte, error)
func Redact(e *Event)
func SQLiteAuditDBForTest(l *SQLiteLogger) *sql.DB
func SetClusterID(ctx context.Context, id string)
func VerifyCommitments(e Event) (checked bool, err error)
func WithActor(ctx context.Context, a Actor) context.Context
type Action string
type ActionCount struct{ ... }
type Actor struct{ ... }
func ActorFromContext(ctx context.Context) Actor
func ActorService(saID, saName string, tenantID tenant.ID) Actor
func ActorSystem(name string) Actor
type ActorType string
const ActorTypeUser ActorType = "user" ...
type ChainMismatchError struct{ ... }
type ClusterIDCapture struct{ ... }
func WithClusterIDCapture(ctx context.Context) (context.Context, *ClusterIDCapture)
type Commitments struct{ ... }
func ComputeCommitments(salt []byte, e Event) Commitments
type Event struct{ ... }
type Filter struct{ ... }
type Logger interface{ ... }
func NewNoopLogger() Logger
func NewSQLiteLogger(dbPath string, opts SQLiteLoggerOptions) (Logger, error)
type NoopLogger struct{}
type Page struct{ ... }
type ResourceType string
const ResourceProject ResourceType = "project" ...
type SQLiteLogger struct{ ... }
type SQLiteLoggerOptions struct{ ... }
type TenantExport struct{ ... }
type VerifyBootResult struct{ ... }
func VerifyChainPostMigration(ctx context.Context, logger Logger) (VerifyBootResult, error)
type VerifyResult struct{ ... }
```

Full documentation, including the prose comments: [`audit` on pkg.go.dev](https://pkg.go.dev/github.com/suryakencana007/tamper/audit).

## `oidc`

The OIDC relying party and its store-backed, per-tenant provider manager.

```text
const StateTTL = 10 * time.Minute ...
var ErrDiscoveryFailed = errors.New("oidc: discovery failed")
var ErrIDTokenInvalid = errors.New("oidc: id token invalid")
var ErrNoKeySet = errors.New("oidc: no keyset configured")
var ErrNonceMismatch = errors.New("oidc: id token nonce does not match flow nonce")
var ErrProviderExists = errors.New("oidc: provider already exists")
var ErrProviderNotFound = errors.New("oidc: provider not found")
var ErrStateExpired = errors.New("oidc: state cookie expired or invalid")
var ErrUnknownProvider = errors.New("oidc: unknown provider")
func ExtractGroups(claims map[string]any, claimName string) []string
func FetchUserinfo(ctx context.Context, p *Provider, accessToken string) (map[string]any, error)
func JSONRawFromClaims(claims *Claims) json.RawMessage
func MergeUserinfoIntoClaims(idClaims *Claims, userinfo map[string]any)
func SignOIDCStateWithSecret(secret []byte, claims StateCookieClaims, issuer string, now time.Time, ...) (string, error)
type Claims struct{ ... }
func VerifyIDToken(ctx context.Context, p *Provider, rawIDToken, expectedNonce string) (*Claims, error)
type CookieSigner interface{ ... }
type DiscoveryResult struct{ ... }
type Flow struct{ ... }
func NewFlow() (*Flow, error)
type Manager struct{ ... }
func NewManager(store ProviderStore, keys *crypto.KeySet, opts ...ManagerOption) *Manager
type ManagerOption func(*Manager)
func WithInheritance(s tenant.Store, allow tenant.Inheritance) ManagerOption
func WithRedirectURL(fn func(id string) string) ManagerOption
func WithRedirectURLForTenant(fn func(tenantID tenant.ID, providerID string) string) ManagerOption
func WithTTL(d time.Duration) ManagerOption
type MemProviderStore struct{ ... }
func NewMemProviderStore() *MemProviderStore
type Provider struct{ ... }
func BuildProvider(ctx context.Context, cfg ProviderConfig) (*Provider, error)
type ProviderConfig struct{ ... }
type ProviderDefinition struct{ ... }
type ProviderRecord struct{ ... }
type ProviderRegistry struct{ ... }
func BuildRegistryFromConfigs(ctx context.Context, providers []ProviderConfig, partialOK bool) (*ProviderRegistry, error)
type ProviderStore interface{ ... }
type ProviderSummary struct{ ... }
type RotateResult struct{ ... }
type StateCookieClaims struct{ ... }
func VerifyOIDCStateWithSecret(secret []byte, token, issuer string, now func() time.Time) (StateCookieClaims, error)
```

Full documentation, including the prose comments: [`oidc` on pkg.go.dev](https://pkg.go.dev/github.com/suryakencana007/tamper/oidc).

## `saml`

The SAML service provider: AuthnRequest, metadata, assertion parsing, replay defence, and the response bound.

```text
const StateTTL = 10 * time.Minute ...
const DefaultMaxSAMLResponseBytes = 1 << 20
var ErrAssertionInvalid = errors.New("saml: assertion invalid")
var ErrAssertionReplayed = errors.New("saml: assertion already consumed")
var ErrIdPInitiatedDisabled = errors.New("saml: idp-initiated sso is disabled for this provider")
var ErrMetadataFetchFailed = errors.New("saml: metadata fetch failed")
var ErrMetadataInvalid = errors.New("saml: metadata invalid")
var ErrNoKeySet = errors.New("saml: no keyset configured")
var ErrNoSubjectConfirmation = errors.New("saml: assertion carries no subject confirmation")
var ErrProviderExists = errors.New("saml: provider already exists")
var ErrProviderNotFound = errors.New("saml: provider not found")
var ErrReplayStoreUnavailable = errors.New("saml: assertion replay store unavailable")
var ErrStateExpired = errors.New("saml: state cookie expired or invalid")
var ErrUncorrelated = errors.New("saml: assertion does not answer this flow's AuthnRequest")
var ErrUnknownProvider = errors.New("saml: unknown provider")
func AttributeValue(a *crewjamsaml.Assertion, name string) string
func AttributeValues(a *crewjamsaml.Assertion, name string) []string
func BuildAuthnRequestURL(p *Provider, relayState string, opts AuthnRequestOptions) (*url.URL, string, error)
func DefaultMetadataFetcher(ctx context.Context, metadataURL string) (*crewjamsaml.EntityDescriptor, error)
func ParseCertPEM(pemStr string) (*x509.Certificate, error)
func ParsePrivateKeyPEM(pemStr string) (any, error)
func SetMaxClockSkew(d time.Duration)
func SignStateCookieWithSecret(secret []byte, claims StateCookieClaims, issuer string, now time.Time, ...) (string, error)
func SubjectNameID(a *crewjamsaml.Assertion) string
type AssertionReplayStore interface{ ... }
type AuthnRequestOptions struct{ ... }
type Manager struct{ ... }
func NewManager(store ProviderStore, keys *tampercrypto.KeySet, opts ...ManagerOption) *Manager
type ManagerOption func(*Manager)
func WithAllowIDPInitiated(v bool) ManagerOption
func WithAssertionReplayStore(s AssertionReplayStore) ManagerOption
func WithInheritance(s tenant.Store, allow tenant.Inheritance) ManagerOption
func WithMetadataFetcher(fn MetadataFetcher) ManagerOption
func WithSPMetadataURL(fn func(id, acsURL string) string) ManagerOption
func WithSPMetadataURLForTenant(fn func(tenantID tenant.ID, id, acsURL string) string) ManagerOption
func WithSkewTolerance(d time.Duration) ManagerOption
func WithTTL(d time.Duration) ManagerOption
type MemAssertionReplayStore struct{ ... }
func NewMemAssertionReplayStore() *MemAssertionReplayStore
type MemProviderStore struct{ ... }
func NewMemProviderStore() *MemProviderStore
type MetadataFetcher func(ctx context.Context, metadataURL string) (*crewjamsaml.EntityDescriptor, error)
type MetadataTestResult struct{ ... }
type NoReplayDefence struct{}
type ParsedAssertion struct{ ... }
type Provider struct{ ... }
func BuildProvider(cfg ProviderConfig, idpMetadata *crewjamsaml.EntityDescriptor, ...) (*Provider, error)
type ProviderConfig struct{ ... }
type ProviderDefinition struct{ ... }
type ProviderOption func(*Provider)
func WithMaxResponseBytes(n int) ProviderOption
func WithMaxResponseBytesUnbounded() ProviderOption
type ProviderRecord struct{ ... }
type ProviderRegistry struct{ ... }
func BuildRegistryFromConfigs(ctx context.Context, configs []ProviderConfig, fetcher MetadataFetcher, ...) (*ProviderRegistry, error)
type ProviderStore interface{ ... }
type ProviderSummary struct{ ... }
type RotateResult struct{ ... }
type StateCookieClaims struct{ ... }
func VerifyStateCookieWithSecret(secret []byte, token, issuer string, nowFn func() time.Time) (StateCookieClaims, error)
```

Full documentation, including the prose comments: [`saml` on pkg.go.dev](https://pkg.go.dev/github.com/suryakencana007/tamper/saml).

## `scim`

The SCIM 2.0 substrate: filter engine, RFC 7644 PATCH, groups with cycle detection — over stores you supply.

```text
const PatchSchemaURN = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
var ErrNotFound = errors.New("scim store: not found") ...
var ErrCyclicGroup = errors.New("scim nesting: cyclic group reference")
var ErrInvalidFilter = errors.New("scim filter: invalid")
var ErrInvalidPath = errors.New("scim patch: invalid path")
var ErrInvalidValue = errors.New("scim patch: invalid value")
func Apply(target map[string]any, ops []Operation) error
func DetectCycle(ctx context.Context, q GroupMemberQueries, parent, candidate string) error
func Parse(query string) (fp.Expression, error)
func Translate(expr fp.Expression, m ColumnMapping) (where string, args []any, err error)
type ColumnMapping struct{ ... }
type Email struct{ ... }
type FilterError struct{ ... }
type GroupMemberQueries interface{ ... }
type GroupPage struct{ ... }
type GroupRecord struct{ ... }
type GroupStore interface{ ... }
type GroupWrite struct{ ... }
type GroupWriteMeta struct{ ... }
type MemberRef struct{ ... }
type NestingError struct{ ... }
type Op string
const OpAdd Op = "add" ...
type Operation struct{ ... }
func RedactedOps(ops []Operation) []Operation
type PatchError struct{ ... }
type Path struct{ ... }
func ParsePath(s string) (*Path, error)
type Request struct{ ... }
type UserPage struct{ ... }
type UserRecord struct{ ... }
type UserStore interface{ ... }
type UserWrite struct{ ... }
type WriteMeta struct{ ... }
```

Full documentation, including the prose comments: [`scim` on pkg.go.dev](https://pkg.go.dev/github.com/suryakencana007/tamper/scim).

## `espresso`

The transport adapter: mountable route surfaces and the middleware that enforces tenancy, authorization, step-up and machine credentials.

```text
const SchemaUser = "urn:ietf:params:scim:schemas:core:2.0:User" ...
const SCIMTypeUniqueness = "uniqueness" ...
const ContentTypeSCIM = "application/scim+json"
const EntitlementDeniedCode = "FEATURE_NOT_ENABLED"
const StepUpErrorCode = "STEP_UP_REQUIRED"
const TenantPathSegment = "{tenant}"
const ThrottledCode = "TOO_MANY_REQUESTS"
var ErrOAuth2State = errors.New("oauth2social: state cookie invalid") ...
var ErrOIDCState = errors.New("oidc: state invalid") ...
var ErrInvalidCredential = errors.New("tamper/espresso: invalid credential")
var ErrThrottled = errors.New("espresso: start-login throttled")
func AccessClaimsFromContext(ctx context.Context) (*crypto.AccessClaims, bool)
func AuditActorFromContext(ctx context.Context) (audit.Actor, bool)
func BuildLandingFragment(code, state, providerID string) string
func CheckIfMatch(r *http.Request, currentETag string) (ok bool, status int, code string)
func ContextWithAccessClaims(ctx context.Context, claims *crypto.AccessClaims) context.Context
func EnteredFromContext(ctx context.Context) (home tenant.ID, entered bool)
func FixedRequestTenant(id tenant.ID) func(*http.Request) (tenant.ID, bool)
func FixedTenant(id tenant.ID) func(context.Context) (tenant.ID, bool)
func FragmentValue(s string) string
func GetRemoteIP(ctx context.Context) string
func GetUserID(ctx context.Context) (string, bool)
func IPFromRequest(r *http.Request) string
func ImpersonatedFromContext(ctx context.Context) (actorHome tenant.ID, actorID string, ok bool)
func MustGetUserID(ctx context.Context) string
func NamedCookieValue(ctx context.Context, slot string) (string, bool)
func NormalizeETag(s string) string
func PinTenant(resolve func(*http.Request) (tenant.ID, bool)) func(http.Handler) http.Handler
func ReadNamedCookie(slot, cookieName string) func(http.Handler) http.Handler
func RemoteIP(extract IPExtractor) func(http.Handler) http.Handler
func RequireActiveTenant(g ActiveTenantGate) func(http.Handler) http.Handler
func RequireAuth(jwt *crypto.JWTService) func(http.Handler) http.Handler
func RequireAuthWS(jwt *crypto.JWTService, subprotocolPrefix string) func(http.Handler) http.Handler
func RequireDecision(g DecisionGate) func(http.Handler) http.Handler
func RequireEntitlement(store tenant.EntitlementStore, capability Capability, ...) func(http.Handler) http.Handler
func RequireFreshAuth(maxAge time.Duration, acrValues []string, opts ...StepUpOption) func(http.Handler) http.Handler
func RequireFreshAuthWithAudit(maxAge time.Duration, acrValues []string, auditLog audit.Logger, ...) func(http.Handler) http.Handler
func RequirePlatformServiceAccount(v ServiceAccountValidator) func(http.Handler) http.Handler
func RequireServiceAccount(v ServiceAccountValidator) func(http.Handler) http.Handler
func RequireTenant(resolve func(*http.Request) (tenant.ID, bool)) func(http.Handler) http.Handler
func RequireTenantAllowEntered(resolve func(*http.Request) (tenant.ID, bool)) func(http.Handler) http.Handler
func RequireTenantAllowEnteredOrImpersonated(resolve func(*http.Request) (tenant.ID, bool)) func(http.Handler) http.Handler
func RequireTenantAllowImpersonated(resolve func(*http.Request) (tenant.ID, bool)) func(http.Handler) http.Handler
func ResolveBaseURL(r *http.Request, override string) string
func ResourceETag(t time.Time) string
func SetAuditActor(ctx context.Context, actor audit.Actor)
func SplitACRValues(raw string) []string
func StartOAuth2Flow(p *oauth2social.Provider, secret []byte, issuer string, now time.Time, ...) (string, *http.Cookie, error)
func StartOIDCFlow(p *oidc.Provider, secret []byte, issuer string, now time.Time, ...) (string, *http.Cookie, error)
func StepUpSatisfied(requestedMaxAge int64, requestedACRValues []string, deliveredAuthTime int64, ...) bool
func TenantFromContext(ctx context.Context) (tenant.ID, bool)
func TenantFromRoutedContext(r *http.Request) (tenant.ID, bool)
func TenantFromServiceAccount(r *http.Request) (tenant.ID, bool)
func ThrottleKeyByRemoteAddr(r *http.Request) string
func ThrottleKeyByRoutedTenant(r *http.Request) string
func ThrottleKeyByServiceAccount(r *http.Request) string
func Throttled(throttle crypto.Throttle, key func(*http.Request) string, ...) func(http.Handler) http.Handler
func WriteETagHeader(w http.ResponseWriter, value string)
func WriteSCIMEntitlementDenied(w http.ResponseWriter, _ *http.Request, c Capability)
func WriteSCIMError(w http.ResponseWriter, status int, detail string)
func WriteSCIMErrorTyped(w http.ResponseWriter, status int, detail, scimType string)
func WriteSCIMJSON(w http.ResponseWriter, status int, body any)
func WriteSCIMThrottled(w http.ResponseWriter, _ *http.Request, retryAfter time.Duration)
type ActiveTenantGate struct{ ... }
type AuditActorCapture struct{ ... }
func WithAuditActorCapture(ctx context.Context) (context.Context, *AuditActorCapture)
type Auditor struct{ ... }
func NewAuditor(logger audit.Logger, emailLookup EmailLookup) *Auditor
type AuthRes struct{ ... }
type AuthResult struct{ ... }
type AuthRoutes struct{ ... }
func NewAuthRoutes(svc IdentityService, cfg AuthRoutesConfig) (*AuthRoutes, error)
type AuthRoutesConfig struct{ ... }
type CallbackParams struct{ ... }
type Capability string
const CapabilitySSO Capability = "sso" ...
type CookieConfig struct{ ... }
type DecisionGate struct{ ... }
type DenyWriter func(w http.ResponseWriter)
type EmailLookup func(ctx context.Context, userID string) (email string, ok bool)
type EntitlementOption func(*entitlementConfig)
func WithEntitlementDenyWriter(fn func(w http.ResponseWriter, r *http.Request, c Capability)) EntitlementOption
type ExchangeReq struct{ ... }
type ExchangeRes struct{ ... }
type FederationBundle struct{ ... }
type FederationConfig struct{ ... }
type FederationHooks struct{ ... }
type FederationOutcome struct{ ... }
type FederationRoutes struct{ ... }
func NewFederationRoutes(cfg FederationConfig, hooks FederationHooks) (*FederationRoutes, error)
type GroupCreateOrReplace struct{ ... }
type GroupMember struct{ ... }
type GroupResource struct{ ... }
type IPExtractor func(*http.Request) string
type IdentityService interface{ ... }
type LinkStartRes struct{ ... }
type ListResponse struct{ ... }
type LoginReq struct{ ... }
type MutationContext struct{ ... }
type OAuth2Verified struct{ ... }
func VerifyOAuth2Callback(ctx context.Context, p *oauth2social.Provider, code, state, cookieVal string, ...) (OAuth2Verified, error)
type OIDCVerified struct{ ... }
func VerifyOIDCCallback(ctx context.Context, p *oidc.Provider, code, state, cookieVal string, ...) (OIDCVerified, error)
type Principal struct{ ... }
func GetPrincipal(ctx context.Context) (Principal, bool)
func MustGetPrincipal(ctx context.Context) Principal
type PrincipalScope string
const PrincipalScopeTenant PrincipalScope = "" ...
type Redirect struct{ ... }
type RegisterReq struct{ ... }
type Resolver = tenant.DomainStore
type ResourceMeta struct{ ... }
type ResourceTypeEntry struct{ ... }
type RouteConfig struct{ ... }
type SAMLAssertionForm struct{ ... }
type SAMLBundle struct{ ... }
type SAMLConfig struct{ ... }
type SAMLHooks struct{ ... }
type SAMLOutcome struct{ ... }
type SAMLRoutes struct{ ... }
func NewSAMLRoutes(cfg SAMLConfig, hooks SAMLHooks) (*SAMLRoutes, error)
type SAMLStartParams struct{ ... }
type SAMLVerified struct{ ... }
type SCIMBundle struct{ ... }
type SCIMConfig struct{ ... }
type SCIMError struct{ ... }
type SCIMRoutes struct{ ... }
func NewSCIMRoutes(cfg SCIMConfig, users scim.UserStore, groups scim.GroupStore) (*SCIMRoutes, error)
type SPCAuthScheme struct{ ... }
type SPCBulk struct{ ... }
type SPCFilter struct{ ... }
type SPCSupported struct{ ... }
type ServiceAccountValidator interface{ ... }
type ServiceProviderConfig struct{ ... }
type StartLoginOption func(*startLoginConfig)
func WithStartLoginClock(now func() time.Time, sleep func(time.Duration)) StartLoginOption
func WithStartLoginFloor(d time.Duration) StartLoginOption
func WithStartLoginTenants(s tenant.Store) StartLoginOption
func WithStartLoginThrottle(t Throttle) StartLoginOption
func WithStartLoginThrottleKey(fn func(email string) string) StartLoginOption
type StartLoginResult struct{ ... }
func StartLogin(ctx context.Context, r Resolver, email string, opts ...StartLoginOption) (StartLoginResult, error)
type StartOptions struct{ ... }
type StartParams struct{ ... }
type StateCookieConfig struct{ ... }
type StepUpDenialReason string
const StepUpDenyStaleAuth StepUpDenialReason = "stale_auth_time" ...
type StepUpOption func(*stepUpConfig)
func StepUpRequireMethods(methods ...string) StepUpOption
func WithStepUpClock(now func() time.Time) StepUpOption
type Surfaces struct{ ... }
func Routes(tp *tamper.Provider, cfg RouteConfig) (*Surfaces, error)
type TOTPDisableReq struct{ ... }
type TOTPEnrollRes struct{ ... }
type TOTPEnrollSessionReq struct{ ... }
type TOTPEnrollSessionRes struct{ ... }
type TOTPEnrollment struct{ ... }
type TOTPVerifyReq struct{ ... }
type Throttle = crypto.Throttle
type ThrottleOption func(*throttleConfig)
func WithThrottleDenyWriter(fn func(w http.ResponseWriter, r *http.Request, retryAfter time.Duration)) ThrottleOption
type UserCreateOrReplace struct{ ... }
type UserEmail struct{ ... }
type UserName struct{ ... }
type UserResource struct{ ... }
type ValidatorFunc func(ctx context.Context, token string) (Principal, error)
type XML struct{ ... }
```

Full documentation, including the prose comments: [`espresso` on pkg.go.dev](https://pkg.go.dev/github.com/suryakencana007/tamper/espresso).

## `oauth2social`

OAuth2 social providers (state + PKCE plumbing), for sign-in with an external identity provider that is not OIDC or SAML.

```text
var ErrConfig = errors.New("oauth2social: invalid provider config") ...
type ClaimMap struct{ ... }
type Config struct{ ... }
func Discord(clientID, clientSecret, redirectURL string) Config
type Provider struct{ ... }
func New(cfg Config) (*Provider, error)
```

Full documentation, including the prose comments: [`oauth2social` on pkg.go.dev](https://pkg.go.dev/github.com/suryakencana007/tamper/oauth2social).

## Versioning

**This site documents one version at a time: the latest release.** The decision, its reasons, and
what would change it:

- **The version is on every page**, generated from `CHANGELOG.md` at build time, so a reader always
  knows which release they are reading without looking for it.
- **Breaking releases ship migration guides** that are part of this site
  ([0.9.0](../migrations/MIGRATION-v0.9), [0.7.0](../migrations/MIGRATION-v0.7),
  [0.4.0](../migrations/MIGRATION-v0.4)), which is where version-specific instructions belong:
  "how do I move from here to there" is a different question from "what is true today".
- **Per-version sites were rejected** for now, and not because they are hard: VitePress can
  publish version directories, and every one of them becomes a surface that must be deployed,
  indexed and kept alive. For a library whose breaking changes are three releases apart and each
  documented in a migration guide, that buys a reader nothing they cannot get from the tag they
  are already pinned to — `https://github.com/suryakencana007/tamper/tree/v0.9.0/docs`.
- **What would change it:** a second supported major line, or a breaking change without a
  migration guide. Either turns "the latest version" into "a version", and at that point the
  maintenance cost of duplicate sites is the smaller problem.

## Where to start

- The [guide](../guide/) explains the shapes; this page is for looking up a name.
- The [design](../design/TAMPER-DESIGN) explains why the packages are split this way.
- [Changelog](../changelog) for what changed, and [migration guides](../migrations/MIGRATION-v0.9)
  for what to do about it.

