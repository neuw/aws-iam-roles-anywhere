package in.neuw.aws.rolesanywhere.credentials;

import software.amazon.awssdk.annotations.NotThreadSafe;
import software.amazon.awssdk.annotations.SdkPublicApi;
import software.amazon.awssdk.annotations.ThreadSafe;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.utils.Logger;
import software.amazon.awssdk.utils.SdkAutoCloseable;
import software.amazon.awssdk.utils.ToString;
import software.amazon.awssdk.utils.Validate;
import software.amazon.awssdk.utils.builder.CopyableBuilder;
import software.amazon.awssdk.utils.builder.ToCopyableBuilder;
import software.amazon.awssdk.utils.cache.CachedSupplier;
import software.amazon.awssdk.utils.cache.NonBlocking;
import software.amazon.awssdk.utils.cache.RefreshResult;
import tools.jackson.databind.json.JsonMapper;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Function;

@ThreadSafe
@SdkPublicApi
public abstract class RolesAnywhereCredentialsProvider implements AwsCredentialsProvider, SdkAutoCloseable {
    private static final Logger log = Logger.loggerFor(RolesAnywhereCredentialsProvider.class);

    private static final Duration DEFAULT_STALE_TIME = Duration.ofMinutes(1);
    private static final Duration DEFAULT_PREFETCH_TIME = Duration.ofMinutes(5);

    /**
     * The RestClient that should be used for periodically updating the session credentials.
     */
    final SdkHttpClient sdkHttpClient;
    final JsonMapper jsonMapper;

    /**
     * The session cache that handles automatically updating the credentials when they get close to expiring.
     */
    private final CachedSupplier<AwsSessionCredentials> sessionCache;

    private final Duration staleTime;
    private final Duration prefetchTime;
    private final boolean asyncCredentialUpdateEnabled;
    private final boolean prefetch;

    RolesAnywhereCredentialsProvider(BaseBuilder<?, ?> builder, String asyncThreadName) {
        this.sdkHttpClient = Validate.notNull(builder.sdkHttpClient, "sdkHttpClient must not be null.");
        this.jsonMapper = Validate.notNull(builder.jsonMapper, "Object Mapper must not be null.");

        this.staleTime = Optional.ofNullable(builder.staleTime).orElse(DEFAULT_STALE_TIME);
        this.prefetchTime = Optional.ofNullable(builder.prefetchTime).orElse(DEFAULT_PREFETCH_TIME);

        this.asyncCredentialUpdateEnabled = builder.asyncCredentialUpdateEnabled;
        this.prefetch = builder.prefetch;
        CachedSupplier.Builder<AwsSessionCredentials> cacheBuilder = CachedSupplier
                .builder(this::updateSessionCredentials)
                .cachedValueName(toString());
        if (this.asyncCredentialUpdateEnabled) {
            cacheBuilder.prefetchStrategy(new NonBlocking(asyncThreadName));
        }
        this.sessionCache = cacheBuilder.build();
    }

    /**
     * Update the expiring session credentials by calling Rest Client. Invoked by {@link CachedSupplier} when the credentials
     * are close to expiring.
     */
    private RefreshResult<AwsSessionCredentials> updateSessionCredentials() {
        AwsSessionCredentials credentials = getUpdatedCredentials();
        Instant actualTokenExpiration =
            credentials.expirationTime()
                       .orElseThrow(() -> new IllegalStateException("Sourced credentials have no expiration value"));

        return RefreshResult.builder(credentials)
                            .staleTime(actualTokenExpiration.minus(staleTime))
                            .prefetchTime(actualTokenExpiration.minus(prefetchTime))
                            .build();
    }

    @Override
    public AwsCredentials resolveCredentials() {
        AwsSessionCredentials credentials = sessionCache.get();
        credentials
                .expirationTime()
                .ifPresent(t -> log.info(() -> "Using Role Anywhere credentials with expiration time of " + t));
        return credentials;
    }

    @Override
    public void close() {
        sessionCache.close();
    }

    /**
     * The amount of time, relative to AWS Session token expiration, that the cached credentials are considered stale and
     * should no longer be used. All threads will block until the value is updated.
     */
    public Duration staleTime() {
        return staleTime;
    }

    /**
     * The amount of time, relative to AWS Session token expiration, that the cached credentials are considered close to stale
     * and should be updated.
     */
    public Duration prefetchTime() {
        return prefetchTime;
    }

    @Override
    public String toString() {
        return ToString.create(providerName());
    }

    /**
     * Implemented by a child class to call Rest Client and get a new set of credentials to be used by this provider.
     */
    abstract AwsSessionCredentials getUpdatedCredentials();

    abstract String providerName();

    void prefetchCredentials() {
        if (prefetch) {
            log.info(() -> "prefetch was enabled, prefetching the credentials");
            sessionCache.get();
        }
    }

    /**
     * Extended by child class's builders to share configuration across credential providers.
     */
    @NotThreadSafe
    @SdkPublicApi
    public abstract static class BaseBuilder<B extends BaseBuilder<B, T>, T extends ToCopyableBuilder<B, T>>
        implements CopyableBuilder<B, T> {
        private final Function<B, T> providerConstructor;

        private boolean asyncCredentialUpdateEnabled;
        private SdkHttpClient sdkHttpClient;
        private JsonMapper jsonMapper;
        private Duration staleTime;
        private Duration prefetchTime = Duration.ofMinutes(5);
        // disabled by default
        private boolean prefetch;

        BaseBuilder(Function<B, T> providerConstructor, RolesAnywhereCredentialsProvider provider) {
            this.providerConstructor = providerConstructor;
            this.prefetchTime = provider.prefetchTime;
            this.asyncCredentialUpdateEnabled = provider.asyncCredentialUpdateEnabled;
            this.sdkHttpClient = provider.sdkHttpClient;
            this.staleTime = provider.staleTime;
            this.jsonMapper = provider.jsonMapper;
        }

        BaseBuilder(Function<B, T> providerConstructor) {
            this.providerConstructor = providerConstructor;
        }

        @SuppressWarnings("unchecked")
        public B sdkHttpClient(SdkHttpClient sdkHttpClient) {
            this.sdkHttpClient = sdkHttpClient;
            return (B) this;
        }

        public B jsonMapper(JsonMapper jsonMapper) {
            this.jsonMapper = jsonMapper;
            return (B) this;
        }

        /**
         * Configure whether the provider should fetch credentials asynchronously in the background. If this is true,
         * threads are less likely to block when credentials are loaded, but additional resources are used to maintain
         * the provider.
         *
         * <p>By default, this is disabled.</p>
         */
        @SuppressWarnings("unchecked")
        public B asyncCredentialUpdateEnabled(Boolean asyncCredentialUpdateEnabled) {
            this.asyncCredentialUpdateEnabled = asyncCredentialUpdateEnabled;
            return (B) this;
        }

        /**
         * Configure the amount of time, relative to Sessions token expiration, that the cached credentials are considered
         * stale and must be updated. All threads will block until the value is updated.
         *
         * <p>By default, this is 1 minute.</p>
         */
        @SuppressWarnings("unchecked")
        public B staleTime(Duration staleTime) {
            this.staleTime = staleTime;
            return (B) this;
        }

        /**
         * Configure the amount of time, relative to Sessions token expiration, that the cached credentials are considered
         * close to stale and should be updated.
         *
         * Prefetch updates will occur between the specified time and the stale time of the provider. Prefetch updates may be
         * asynchronous. See {@link #asyncCredentialUpdateEnabled}.
         *
         * <p>By default, this is 5 minutes.</p>
         */
        @SuppressWarnings("unchecked")
        public B prefetchTime(Duration prefetchTime) {
            this.prefetchTime = prefetchTime;
            return (B) this;
        }

        public B prefetch(boolean prefetch) {
            this.prefetch = prefetch;
            return (B) this;
        }

        /**
         * Build the credentials provider using the configuration applied to this builder.
         */
        @SuppressWarnings("unchecked")
        public T build() {
            return providerConstructor.apply((B) this);
        }
    }
}