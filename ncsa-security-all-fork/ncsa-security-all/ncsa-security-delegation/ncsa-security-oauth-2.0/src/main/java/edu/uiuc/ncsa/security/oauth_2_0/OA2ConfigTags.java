package edu.uiuc.ncsa.security.oauth_2_0;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/28/14 at  10:37 AM
 */
public interface OA2ConfigTags {
    public String REFRESH_TOKEN_LIFETIME = "refreshTokenLifetime"; // in seconds, convert to ms.
    public String REFRESH_TOKEN_ENABLED = "refreshTokenEnabled"; // Enable or disable refresh tokens for this server.
    public String CLIENT_SECRET_LENGTH= "clientSecretLength"; // in bytes.

    /*
     * Tags for scopes element of configuration
     */
    /**
     * Tope level tag for all scopes
     */
    public String SCOPES = "scopes";
    /**
     * Tag for an individual scope.
     */
    public String SCOPE = "scope";
    /**
     * (Optional) the fully qualified path and class name of the handler for these scopes. Note
     * that only one handler for all scopes is allowed. If this is not found in the classpath,
     * then an error will be raised. Alternately, you can simply override the configuration loader
     * and specify your handler directly.
     */
    public String SCOPE_HANDLER = "handler";

}
