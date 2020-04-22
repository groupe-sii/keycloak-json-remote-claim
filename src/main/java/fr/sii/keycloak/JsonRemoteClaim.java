package fr.sii.keycloak;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.http.HttpHeaders;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.keycloak.utils.MediaType;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:ni.roussel@gmail.com">Nicolas Roussel</a>
 * @version $Revision: 1 $
 */
public class JsonRemoteClaim extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    private final static String REMOTE_URL = "remote.url";
    private final static String REMOTE_HEADERS = "remote.headers";
    private final static String REMOTE_PARAMETERS = "remote.parameters";
    private final static String REMOTE_PARAMETERS_USERNAME = "remote.parameters.username";
    private final static String REMOTE_PARAMETERS_CLIENTID = "remote.parameters.clientid";
    private static final String REMOTE_PARAMETERS_USER_ATTRIBUTES = "remote.parameters.user.attributes";
    private static final String REMOTE_HEADERS_BEARER_TOKEN = "remote.headers.bearer.token";
    private static final String CLIENT_AUTH_URL = "client.auth.url";
    private static final String CLIENT_AUTH_ID = "client.auth.id";
    private static final String CLIENT_AUTH_PASS = "client.auth.pass";


    /**
     * Inner configuration to cache retrieved authorization for multiple tokens
     */
    private final static String REMOTE_AUTHORIZATION_ATTR = "remote-authorizations";

    /*
     * ID of the token mapper.
     * Must be public
     */
    public final static String PROVIDER_ID = "json-remote-claim";

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, JsonRemoteClaim.class);
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);

        ProviderConfigProperty property;

        // Username
        property = new ProviderConfigProperty();
        property.setName(REMOTE_PARAMETERS_USERNAME);
        property.setLabel("Send user name");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Send the username as query parameter (param: username).");
        property.setDefaultValue("true");
        configProperties.add(property);

        // Client_id
        property = new ProviderConfigProperty();
        property.setName(REMOTE_PARAMETERS_CLIENTID);
        property.setLabel("Send client ID");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Send the client_id as query parameter (param: client_id).");
        property.setDefaultValue("false");
        configProperties.add(property);

        // User attributes
        property = new ProviderConfigProperty();
        property.setName(REMOTE_PARAMETERS_USER_ATTRIBUTES);
        property.setLabel("User attributes");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Send custom user attributes as query parameter. Separate value by '&' sign.");
        configProperties.add(property);

        // URL
        property = new ProviderConfigProperty();
        property.setName(REMOTE_URL);
        property.setLabel("URL");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Full URL of the remote service endpoint.");
        configProperties.add(property);

        // Parameters
        property = new ProviderConfigProperty();
        property.setName(REMOTE_PARAMETERS);
        property.setLabel("Parameters");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("List of query parameters to send separated by '&'. Separate parameter name and value by an equals sign '=', the value can contain equals signs (ex: scope=all&full=true).");
        configProperties.add(property);

        // Headers
        property = new ProviderConfigProperty();
        property.setName(REMOTE_HEADERS);
        property.setLabel("Headers");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("List of headers to send separated by '&'. Separate header name and value by an equals sign '=', the value can contain equals signs (ex: Authorization=az89d).");
        configProperties.add(property);

        // Bearer token
        property = new ProviderConfigProperty();
        property.setName(REMOTE_HEADERS_BEARER_TOKEN);
        property.setLabel("Send bearer token");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Send the bearer token as auth header.");
        configProperties.add(property);

        // Client auth url
        property = new ProviderConfigProperty();
        property.setName(CLIENT_AUTH_URL);
        property.setLabel("Client auth URL");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Full URL of the keycloak client auth endpoint.");
        configProperties.add(property);

        // Client id
        property = new ProviderConfigProperty();
        property.setName(CLIENT_AUTH_ID);
        property.setLabel("Client id");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Client id to create a tech token.");
        configProperties.add(property);

        // Client password
        property = new ProviderConfigProperty();
        property.setName(CLIENT_AUTH_PASS);
        property.setLabel("Client password");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Client password to create a tech token.");
        configProperties.add(property);
    }

    @Override
    public String getDisplayCategory() {
        return "Token mapper";
    }

    @Override
    public String getDisplayType() {
        return "JSON Remote claim";
    }

    @Override
    public String getHelpText() {
        return "Retrieve JSON data to include from a remote HTTP endpoint.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        JsonNode claims = clientSessionCtx.getAttribute(REMOTE_AUTHORIZATION_ATTR, JsonNode.class);
        if (claims == null) {
            claims = getRemoteAuthorizations(mappingModel, userSession, clientSessionCtx);
            clientSessionCtx.setAttribute(REMOTE_AUTHORIZATION_ATTR, claims);
        }

        OIDCAttributeMapperHelper.mapClaim(token, mappingModel, claims);
    }

    /**
     * Deprecated, added for older versions
     *
     * Caution: This version does not allow to minimize request number
     *
     * @deprecated override {@link #setClaim(IDToken, ProtocolMapperModel, UserSessionModel, KeycloakSession, ClientSessionContext)} instead.
     */
    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession) {
        JsonNode claims = getRemoteAuthorizations(mappingModel, userSession, null);
        OIDCAttributeMapperHelper.mapClaim(token, mappingModel, claims);
    }

    private Map<String, String> getQueryParameters(ProtocolMapperModel mappingModel, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        final String configuredParameter = mappingModel.getConfig().get(REMOTE_PARAMETERS);
        final boolean sendUsername = "true".equals(mappingModel.getConfig().get(REMOTE_PARAMETERS_USERNAME));
        final boolean sendClientID = "true".equals(mappingModel.getConfig().get(REMOTE_PARAMETERS_CLIENTID));
        final String configuredUserAttributes = mappingModel.getConfig().get(REMOTE_PARAMETERS_USER_ATTRIBUTES);

        // Get parameters
        final Map<String, String> formattedParameters = Utils.buildMapFromStringConfig(configuredParameter);

        // Get client ID
        if (sendClientID) {
            if (clientSessionCtx != null) {
                formattedParameters.put("client_id", clientSessionCtx.getClientSession().getClient().getId());
            } else {
                formattedParameters.put("client_id", userSession.getAuthenticatedClientSessions().values().stream()
                        .map(AuthenticatedClientSessionModel::getClient)
                        .map(ClientModel::getClientId)
                        .distinct()
                        .collect(Collectors.joining(",")));
            }
        }

        // Get username
        if (sendUsername) {
            formattedParameters.put("username", userSession.getLoginUsername());
        }

        // Get custom user attributes
        if (configuredUserAttributes != null && !"".equals(configuredUserAttributes.trim())) {
            List<String> userAttributes = Arrays.asList(configuredUserAttributes.trim().split("&"));
            userAttributes.forEach(attribute -> formattedParameters.put(attribute, userSession.getUser().getFirstAttribute(attribute)));
        }
        return formattedParameters;
    }

    private Map<String, String> getheaders(ProtocolMapperModel mappingModel, UserSessionModel userSession) {
        final String configuredHeaders = mappingModel.getConfig().get(REMOTE_HEADERS);
        final boolean sendBearerToken = "true".equals(mappingModel.getConfig().get(REMOTE_HEADERS_BEARER_TOKEN));

        // Get headers
        Map<String, String> stringStringMap = Utils.buildMapFromStringConfig(configuredHeaders);
        if (sendBearerToken) {
            String signedRequestToken = getClientToken(mappingModel);
            stringStringMap.put(HttpHeaders.AUTHORIZATION, "Bearer " + signedRequestToken);
        }
        return stringStringMap;
    }

    private String getClientToken(ProtocolMapperModel mappingModel) {
        // Get parameters
        Map<String, String> parameters = new HashMap<>();
        // Get headers
        Map<String, String> headers = new HashMap<>();

        Map<String, String> formParameters = new HashMap<>();
        formParameters.put("grant_type", "client_credentials");
        formParameters.put("client_id", mappingModel.getConfig().get(CLIENT_AUTH_ID));
        formParameters.put("client_secret", mappingModel.getConfig().get(CLIENT_AUTH_PASS));

        // Call remote service
        String baseUrl = mappingModel.getConfig().get(CLIENT_AUTH_URL);
        JsonNode jsonNode = HttpHandler.getJsonNode(baseUrl, MediaType.APPLICATION_FORM_URLENCODED, headers, parameters, formParameters);
        if (!jsonNode.has("access_token")) {
            throw new JsonRemoteClaimException("Access token not found", baseUrl);
        }
        return jsonNode.findValue("access_token").asText();
    }

    private JsonNode getRemoteAuthorizations(ProtocolMapperModel mappingModel, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        // Get parameters
        Map<String, String> parameters = getQueryParameters(mappingModel, userSession, clientSessionCtx);
        // Get headers
        Map<String, String> headers = getheaders(mappingModel, userSession);

        // Call remote service
        String baseUrl = mappingModel.getConfig().get(REMOTE_URL);
        return HttpHandler.getJsonNode(baseUrl, MediaType.APPLICATION_JSON, headers, parameters, null);
    }
}
