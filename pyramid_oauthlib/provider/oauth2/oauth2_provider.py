# coding: utf-8
"""
    pyramid_oauthlib.provider.oauth2
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implements OAuth2 provider support for Pyramid.

    :copyright: (c) 2013 by Simone Marzola.
"""

import os
import logging
import datetime
from oauthlib.oauth2 import RequestValidator, Server
from oauthlib.common import to_unicode
from pyramid.decorator import reify
from pyramid.threadlocal import get_current_registry
from pyramid_oauthlib.provider.oauth2.interfaces import IOAuth2Provider, IOAuth2DataProvider, IOAuth2Validator
from zope.interface import implementer
from pyramid_oauthlib.utils import decode_base64

__all__ = ('OAuth2Provider', 'OAuth2RequestValidator')

log = logging.getLogger('pyramid_oauthlib')


@implementer(IOAuth2Provider)
class OAuth2Provider(object):

    def __init__(self, oauth_data_provider):
        self.oauth_data_provider = oauth_data_provider

    @reify
    def server(self):
        registry = get_current_registry()
        request_validator = registry.queryUtility(IOAuth2Validator)
        return Server(request_validator())


@implementer(IOAuth2Validator)
class OAuth2RequestValidator(RequestValidator):
    def __init__(self):
        self.data_provider = get_current_registry().queryUtility(IOAuth2DataProvider)()

    def authenticate_client(self, request, *args, **kwargs):
        """Authenticate itself in other means.

        Other means means is described in `Section 3.2.1`_.

        .. _`Section 3.2.1`: http://tools.ietf.org/html/rfc6749#section-3.2.1
        """
        auth = request.headers.get('Authorization', None)
        log.debug('Authenticate client %r', auth)
        if auth:
            try:
                _, s = auth.split(' ')
                client_id, client_secret = decode_base64(s).split(':')
                client_id = to_unicode(client_id, 'utf-8')
                client_secret = to_unicode(client_secret, 'utf-8')
            except Exception as e:
                log.debug('Authenticate client failed with exception: %r', e)
                return False
        else:
            client_id = request.client_id
            client_secret = request.client_secret

        client = self.data_provider.get_client(client_id)
        if not client:
            log.debug('Authenticate client failed, client not found.')
            return False

        request.client = client
        if client.client_secret != client_secret:
            log.debug('Authenticate client failed, secret not match.')
            return False

        if client.client_type != 'confidential':
            log.debug('Authenticate client failed, not confidential.')
            return False
        log.debug('Authenticate client success.')
        return True

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """Authenticate a non-confidential client.

        :param client_id: Client ID of the non-confidential client
        :param request: The Request object passed by oauthlib
        """
        log.debug('Authenticate client %r.', client_id)
        client = request.client or self.data_provider.get_client(client_id)
        if not client:
            log.debug('Authenticate failed, client not found.')
            return False

        # attach client on request for convenience
        request.client = client

        # authenticate non-confidential client_type only
        # most of the clients are of public client_type
        if client.client_type == 'confidential':
            log.debug('Authenticate client failed, confidential client.')
            return False
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client,
                             *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri.

        This method is used in the authorization code grant flow. It will
        compare redirect_uri and the one in grant token strictly, you can
        add a `validate_redirect_uri` function on grant for a customized
        validation.
        """
        log.debug('Confirm redirect uri for client %r and code %r.',
                  client_id, code)
        grant = self.data_provider.get_grant(client_id=client_id, code=code)
        if not grant:
            log.debug('Grant not found.')
            return False
        if hasattr(grant, 'validate_redirect_uri'):
            return grant.validate_redirect_uri(redirect_uri)
        log.debug('Compare redirect uri for grant %r and %r.',
                  grant.redirect_uri, redirect_uri)

        if os.environ.get('DEBUG') and redirect_uri is None:
            # For testing
            return True

        return grant.redirect_uri == redirect_uri

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        """Get the list of scopes associated with the refresh token.

        This method is used in the refresh token grant flow.  We return
        the scope of the token to be refreshed so it can be applied to the
        new access token.
        """
        log.debug('Obtaining scope of refreshed token.')
        tok = self.data_provider.get_token(refresh_token=refresh_token)
        return tok.scopes

    def confirm_scopes(self, refresh_token, scopes, request, *args, **kwargs):
        """Ensures the requested scope matches the scope originally granted
        by the resource owner. If the scope is omitted it is treated as equal
        to the scope originally granted by the resource owner.

        DEPRECATION NOTE: This method will cease to be used in oauthlib>0.4.2,
        future versions of ``oauthlib`` use the validator method
        ``get_original_scopes`` to determine the scope of the refreshed token.
        """
        if not scopes:
            log.debug('Scope omitted for refresh token %r', refresh_token)
            return True
        log.debug('Confirm scopes %r for refresh token %r',
                  scopes, refresh_token)
        tok = self.data_provider.get_token(refresh_token=refresh_token)
        return set(tok.scopes) == set(scopes)

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """Default redirect_uri for the given client."""
        request.client = request.client or self.data_provider.get_client(client_id)
        redirect_uri = request.client.default_redirect_uri
        log.debug('Found default redirect uri %r', redirect_uri)
        return redirect_uri

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        """Default scopes for the given client."""
        request.client = request.client or self.data_provider.get_client(client_id)
        scopes = request.client.default_scopes
        log.debug('Found default scopes %r', scopes)
        return scopes

    def invalidate_authorization_code(self, client_id, code, request,
                                      *args, **kwargs):
        """Invalidate an authorization code after use.

        We keep the temporary code in a grant, which has a `delete`
        function to destroy itself.
        """
        log.debug('Destroy grant token for client %r, %r', client_id, code)
        grant = self.data_provider.get_grant(client_id=client_id, code=code)
        if grant:
            grant.delete()

    def save_authorization_code(self, client_id, code, request,
                                *args, **kwargs):
        """Persist the authorization code."""
        log.debug(
            'Persist authorization code %r for client %r',
            code, client_id
        )
        request.client = request.client or self.data_provider.get_client(client_id)
        self.data_provider.set_grant(client_id, code, request, *args, **kwargs)
        return request.client.default_redirect_uri

    def save_bearer_token(self, token, request, *args, **kwargs):
        """Persist the Bearer token."""
        log.debug('Save bearer token %r', token)
        self.data_provider.set_token(token, request, *args, **kwargs)
        return request.client.default_redirect_uri

    def validate_bearer_token(self, token, scopes, request):
        """Validate access token.

        :param token: A string of random characters
        :param scopes: A list of scopes
        :param request: The Request object passed by oauthlib

        The validation validates:

            1) if the token is available
            2) if the token has expired
            3) if the scopes are available
        """
        log.debug('Validate bearer token %r', token)
        tok = self.data_provider.get_token(access_token=token)
        if not tok:
            log.debug('Bearer token not found.')
            return False

        # validate expires
        if datetime.datetime.utcnow() > tok.expires:
            log.debug('Bearer token is expired.')
            return False

        # validate scopes
        if not set(tok.scopes).issuperset(set(scopes)):
            log.debug('Bearer token scope not valid.')
            return False

        request.access_token = tok
        request.user = tok.user
        request.scopes = scopes

        if hasattr(tok, 'client'):
            request.client = tok.client
        elif hasattr(tok, 'client_id'):
            request.client = self.data_provider.get_client(tok.client_id)
        return True

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a valid and active client."""
        log.debug('Validate client %r', client_id)
        client = request.client or self.data_provider.get_client(client_id)
        if client:
            # attach client to request object
            request.client = client
            return True
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        """Ensure the grant code is valid."""
        log.debug(
            'Validate code for client %r and code %r', client_id, code
        )
        grant = self.data_provider.get_grant(client_id=client_id, code=code)
        if not grant:
            log.debug('Grant not found.')
            return False
        if hasattr(grant, 'expires') and \
           datetime.datetime.utcnow() > grant.expires:
            log.debug('Grant is expired.')
            return False

        request.state = kwargs.get('state')
        request.user = grant.user
        request.scopes = grant.scopes
        return True

    def validate_grant_type(self, client_id, grant_type, client, request,
                            *args, **kwargs):
        """Ensure the client is authorized to use the grant type requested.

        It will allow any of the four grant types (`authorization_code`,
        `password`, `client_credentials`, `refresh_token`) by default.
        Implemented `allowed_grant_types` for client object to authorize
        the request.

        It is suggested that `allowed_grant_types` should contain at least
        `authorization_code` and `refresh_token`.
        """
        if self.data_provider.get_user is None and grant_type == 'password':
            log.debug('Password credential authorization is disabled.')
            return False

        if grant_type not in ('authorization_code', 'password',
                              'client_credentials', 'refresh_token'):
            return False

        if hasattr(client, 'allowed_grant_types'):
            return grant_type in client.allowed_grant_types

        if grant_type == 'client_credentials':
            if hasattr(client, 'user'):
                request.user = client.user
                return True
            log.debug('Client should has a user property')
            return False

        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request,
                              *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri.

        This method is used in the authorization code grant flow and also
        in implicit grant flow. It will detect if redirect_uri in client's
        redirect_uris strictly, you can add a `validate_redirect_uri`
        function on grant for a customized validation.
        """
        request.client = request.client = self.data_provider.get_client(client_id)
        client = request.client
        if hasattr(client, 'validate_redirect_uri'):
            return client.validate_redirect_uri(redirect_uri)
        return redirect_uri in client.redirect_uris

    def validate_refresh_token(self, refresh_token, client, request,
                               *args, **kwargs):
        """Ensure the token is valid and belongs to the client

        This method is used by the authorization code grant indirectly by
        issuing refresh tokens, resource owner password credentials grant
        (also indirectly) and the refresh token grant.
        """

        token = self.data_provider.get_token(refresh_token=refresh_token)

        if token and token.client_id == client.client_id:
            # Make sure the request object contains user and client_id
            request.client_id = token.client_id
            request.user = token.user
            return True
        return False

    def validate_response_type(self, client_id, response_type, client, request,
                               *args, **kwargs):
        """Ensure client is authorized to use the response type requested.

        It will allow any of the two (`code`, `token`) response types by
        default. Implemented `allowed_response_types` for client object
        to authorize the request.
        """
        if response_type not in ('code', 'token'):
            return False

        if hasattr(client, 'allowed_response_types'):
            return response_type in client.allowed_response_types
        return True

    def validate_scopes(self, client_id, scopes, client, request,
                        *args, **kwargs):
        """Ensure the client is authorized access to requested scopes."""
        if set(client.default_scopes).issuperset(set(scopes)):
            return True
        if hasattr(client, 'validate_scopes'):
            return client.validate_scopes(scopes)
        return True

    def validate_user(self, username, password, client, request,
                      *args, **kwargs):
        """Ensure the username and password is valid.

        Attach user object on request for later using.
        """
        log.debug('Validating username %r and password %r',
                  username, password)
        if self.data_provider.get_user is not None:
            user = self.data_provider.get_user(
                username, password, client, request, *args, **kwargs
            )
            if user:
                request.user = user
                return True
            return False
        log.debug('Password credential authorization is disabled.')
        return False
