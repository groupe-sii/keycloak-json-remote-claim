package fr.sii.keycloak;

/**
 * @author <a href="mailto:ni.roussel@gmail.com">Nicolas Roussel</a>
 * @version $Revision: 1 $
 */
public class JsonRemoteClaimException extends RuntimeException {

    public JsonRemoteClaimException(String message, String url) {
        super(message + " - Configured URL: " + url);
    }

    public JsonRemoteClaimException(String message, String url, Throwable cause) {
        super(message + " - Configured URL: " + url, cause);
    }

}