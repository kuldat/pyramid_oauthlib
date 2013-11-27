from zope.interface import Interface, Attribute


class IOAuth2Provider(Interface):

    server = Attribute("""oauthlib.oauth2.Server instance""")


class IOAuth2DataProvider(Interface):

    def get_client(client_id, *args, **kw):
        """Client getter function.

        Accepts one parameter `client_id`, and returns
        a client object with at least these information:

            - client_id: A random string
            - client_secret: A random string
            - client_type: A string represents if it is `confidential`
            - redirect_uris: A list of redirect uris
            - default_redirect_uri: One of the redirect uris
            - default_scopes: Default scopes of the client

        The client may contain more information, which is suggested:

            - allowed_grant_types: A list of grant types
            - allowed_response_types: A list of response types
            - validate_scopes: A function to validate scopes
        """

    def get_user(username, password, *args, **kw):
        """User getter function.

        Required for password credential authorization
        """

    def get_token(access_token=None, refresh_token=None):
        """Token getter function.

        Accepts an `access_token` or `refresh_token` parameters,
        and returns a token object with at least these information:

            - access_token: A string token
            - refresh_token: A string token
            - client_id: ID of the client
            - scopes: A list of scopes
            - expires: A `datetime.datetime` object
            - user: The user object
        """

    def set_token(token, request):
        """Save the bearer token.

        Accepts two parameters at least, one is token,
        the other is request::

            @oauth.tokensetter
            def set_token(token, request, *args, **kwargs):
                save_token(token, request.client, request.user)

        The parameter token is a dict, that looks like::

            {
                u'access_token': u'6JwgO77PApxsFCU8Quz0pnL9s23016',
                u'token_type': u'Bearer',
                u'expires_in': 3600,
                u'scope': u'email address'
            }

        The request is an object, that contains an user object and a
        client object.
        """

    def get_grant(client_id, code, *args, **kw):
        """Grant getter function.

        The function accepts `client_id`, `code` and more

        It returns a grant object with at least these information:

            - delete: A function to delete itself
        """

    def set_grant(client_id, code, request, *args, **kwargs):
        """Grant setter function.

        The function accepts `client_id`, `code`, `request` and more::
        """
        
class IOAuth2Validator(Interface):
    def authenticate_client(self, request, *args, **kwargs):
        """Authenticate client through means outside the OAuth 2 spec.

        Means of authentication is negotiated beforehand and may for example
        be `HTTP Basic Authentication Scheme`_ which utilizes the Authorization
        header.

        Headers may be accesses through request.headers and parameters found in
        both body and query can be obtained by direct attribute access, i.e.
        request.client_id for client_id in the URL query.

        OBS! Certain grant types rely on this authentication, possibly with
        other fallbacks, and for them to recognize this authorization please
        set the client attribute on the request (request.client). Note that
        preferably this client object should have a client_id attribute of
        unicode type (request.client.client_id).

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant (may be disabled)
            - Client Credentials Grant
            - Refresh Token Grant

        .. _`HTTP Basic Authentication Scheme`: http://tools.ietf.org/html/rfc1945#section-11.1
        """

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a non-confidential client.

        A non-confidential client is one that is not required to authenticate
        through other means, such as using HTTP Basic.

        Note, while not strictly necessary it can often be very convenient
        to set request.client to the client object associated with the
        given client_id.

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
        """

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client,
            request, *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri requested.

        If the client specifies a redirect_uri when obtaining code then
        that redirect URI must be bound to the code and verified equal
        in this method.

        All clients should register the absolute URIs of all URIs they intend
        to redirect to. The registration is outside of the scope of oauthlib.

        :param client_id: Unicode client identifier
        :param code: Unicode authorization_code.
        :param redirect_uri: Unicode absolute URI
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant (during token request)
        """

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """Get the default redirect URI for the client.

        :param client_id: Unicode client identifier
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: The default redirect URI for the client

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        """Get the default scopes for the client.

        :param client_id: Unicode client identifier
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: List of default scopes

        Method is used by all core grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials grant
        """

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        """Get the list of scopes associated with the refresh token.

        :param refresh_token: Unicode refresh token
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: List of scopes.

        Method is used by:
            - Refresh token grant
        """

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        """Invalidate an authorization code after use.

        :param client_id: Unicode client identifier
        :param code: The authorization code grant (request.code).
        :param request: The HTTP Request (oauthlib.common.Request)

        Method is used by:
            - Authorization Code Grant
        """

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        """Persist the authorization_code.

        The code should at minimum be associated with:
            - a client and it's client_id
            - the redirect URI used (request.redirect_uri)
            - whether the redirect URI used is the client default or not
            - a resource owner / user (request.user)
            - authorized scopes (request.scopes)

        The authorization code grant dict (code) holds at least the key 'code'::

            {'code': 'sdf345jsdf0934f'}

        :param client_id: Unicode client identifier
        :param code: A dict of the authorization code grant.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: The default redirect URI for the client

        Method is used by:
            - Authorization Code Grant
        """

    def save_bearer_token(self, token, request, *args, **kwargs):
        """Persist the Bearer token.

        The Bearer token should at minimum be associated with:
            - a client and it's client_id, if available
            - a resource owner / user (request.user)
            - authorized scopes (request.scopes)
            - an expiration time
            - a refresh token, if issued

        The Bearer token dict may hold a number of items::

            {
                'token_type': 'Bearer',
                'access_token': 'askfjh234as9sd8',
                'expires_in': 3600,
                'scope': 'string of space separated authorized scopes',
                'refresh_token': '23sdf876234',  # if issued
                'state': 'given_by_client',  # if supplied by client
            }

        Note that while "scope" is a string-separated list of authorized scopes,
        the original list is still available in request.scopes

        :param client_id: Unicode client identifier
        :param token: A Bearer token dict
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: The default redirect URI for the client

        Method is used by all core grant types issuing Bearer tokens:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant (might not associate a client)
            - Client Credentials grant
        """

    def validate_bearer_token(self, token, scopes, request):
        """Ensure the Bearer token is valid and authorized access to scopes.

        :param token: A string of random characters.
        :param scopes: A list of scopes associated with the protected resource.
        :param request: The HTTP Request (oauthlib.common.Request)

        A key to OAuth 2 security and restricting impact of leaked tokens is
        the short expiration time of tokens, *always ensure the token has not
        expired!*.

        Two different approaches to scope validation:

            1) all(scopes). The token must be authorized access to all scopes
                            associated with the resource. For example, the
                            token has access to ``read-only`` and ``images``,
                            thus the client can view images but not upload new.
                            Allows for fine grained access control through
                            combining various scopes.

            2) any(scopes). The token must be authorized access to one of the
                            scopes associated with the resource. For example,
                            token has access to ``read-only-images``.
                            Allows for fine grained, although arguably less
                            convenient, access control.

        A powerful way to use scopes would mimic UNIX ACLs and see a scope
        as a group with certain privileges. For a restful API these might
        map to HTTP verbs instead of read, write and execute.

        Note, the request.user attribute can be set to the resource owner
        associated with this token. Similarly the request.client and
        request.scopes attribute can be set to associated client object
        and authorized scopes. If you then use a decorator such as the
        one provided for django these attributes will be made available
        in all protected views as keyword arguments.

        :param token: Unicode Bearer token
        :param scopes: List of scopes (defined by you)
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is indirectly used by all core Bearer token issuing grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
        """

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a valid and active client.

        Note, while not strictly necessary it can often be very convenient
        to set request.client to the client object associated with the
        given client_id.

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        """Ensure the authorization_code is valid and assigned to client.

        OBS! The request.user attribute should be set to the resource owner
        associated with this authorization code. Similarly request.scopes and
        request.state must also be set.

        :param client_id: Unicode client identifier
        :param code: Unicode authorization code
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
        """

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        """Ensure client is authorized to use the grant_type requested.

        :param client_id: Unicode client identifier
        :param grant_type: Unicode grant type, i.e. authorization_code, password.
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
            - Refresh Token Grant
        """

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri requested.

        All clients should register the absolute URIs of all URIs they intend
        to redirect to. The registration is outside of the scope of oauthlib.

        :param client_id: Unicode client identifier
        :param redirect_uri: Unicode absolute URI
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        """Ensure the Bearer token is valid and authorized access to scopes.

        OBS! The request.user attribute should be set to the resource owner
        associated with this refresh token.

        :param refresh_token: Unicode refresh token
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant (indirectly by issuing refresh tokens)
            - Resource Owner Password Credentials Grant (also indirectly)
            - Refresh Token Grant
        """

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        """Ensure client is authorized to use the response_type requested.

        :param client_id: Unicode client identifier
        :param response_type: Unicode response type, i.e. code, token.
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        """Ensure the client is authorized access to requested scopes.

        :param client_id: Unicode client identifier
        :param scopes: List of scopes (defined by you)
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by all core grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
        """

    def validate_user(self, username, password, client, request, *args, **kwargs):
        """Ensure the username and password is valid.

        OBS! The validation should also set the user attribute of the request
        to a valid resource owner, i.e. request.user = username or similar. If
        not set you will be unable to associate a token with a user in the
        persistance method used (commonly, save_bearer_token).

        :param username: Unicode username
        :param password: Unicode password
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Resource Owner Password Credentials Grant
        """