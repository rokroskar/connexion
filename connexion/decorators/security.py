# Authentication and authorization related decorators
import functools
import logging
import os
import textwrap

import requests

from ..exceptions import OAuthProblem, OAuthResponseProblem, OAuthScopeProblem

logger = logging.getLogger('connexion.api.security')

# use connection pool for OAuth tokeninfo
adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
session = requests.Session()
session.mount('http://', adapter)
session.mount('https://', adapter)


def get_tokeninfo_url(security_definition):
    '''
    :type security_definition: dict
    :rtype: str

    >>> get_tokeninfo_url({'x-tokenInfoUrl': 'foo'})
    'foo'
    '''
    token_info_url = (security_definition.get('x-tokenInfoUrl')
                      or os.environ.get('TOKENINFO_URL'))
    return token_info_url


def get_client_credentials(security_definition):
    """
    Get client credentials from security definition

    :type security_definition: dict
    :rtype: dict
    """
    client_id = (security_definition.get('x-clientId') or None)
    client_secret = (security_definition.get('x-clientSecret') or None)
    return {'client_id': client_id, 'client_secret': client_secret}


def security_passthrough(function):
    """
    :type function: types.FunctionType
    :rtype: types.FunctionType
    """
    return function


def verify_oauth(token_info_url, allowed_scopes, client_credentials, function):
    """
    Decorator to verify oauth

    :param token_info_url: Url to get information about the token
    :type token_info_url: str
    :param allowed_scopes: Set with scopes that are allowed to access the endpoint
    :type allowed_scopes: set
    :type client_credentials: dict
    :type function: types.FunctionType
    :rtype: types.FunctionType
    """

    @functools.wraps(function)
    def wrapper(request):
        logger.debug("%s Oauth verification...", request.url)
        authorization = request.headers.get('Authorization')  # type: str
        if not authorization:
            logger.info("... No auth provided. Aborting with 401.")
            raise OAuthProblem(description='No authorization token provided')
        else:
            try:
                _, token = authorization.split()  # type: str, str
            except ValueError:
                raise OAuthProblem(description='Invalid authorization header')
            logger.debug("... Getting token from %s", token_info_url)

            if all(client_credentials.values()):
                method = 'POST'
                auth = (client_credentials['client_id'],
                        client_credentials['client_secret'])
                data = {'token': token}
                params = None
            else:
                method = 'GET'
                params = {'access_token': token}

            token_request = session.request(
                method, token_info_url, auth=auth, data=data, params=params)

            logger.debug("... Token info (%d): %s", token_request.status_code,
                         token_request.text)
            if not token_request.ok:
                raise OAuthResponseProblem(
                    description='Provided oauth token is not valid',
                    token_response=token_request)
            token_info = token_request.json()  # type: dict

            # TODO: keycloak doesn't seem to return scopes, so we check roles
            if isinstance(token_info['realm_access']['roles'], list):
                user_scopes = set(token_info['realm_access']['roles'])
            else:
                user_scopes = set(token_info['realm_access']['roles'].split())
            logger.debug("... Scopes required: %s", allowed_scopes)
            logger.debug("... User scopes: %s", user_scopes)
            if not allowed_scopes <= user_scopes:
                logger.info(
                    textwrap.dedent("""
                            ... User scopes (%s) do not match the scopes necessary to call endpoint (%s).
                             Aborting with 403.""").replace('\n', ''),
                    user_scopes, allowed_scopes)
                raise OAuthScopeProblem(
                    description=
                    'Provided token doesn\'t have the required scope',
                    required_scopes=allowed_scopes,
                    token_scopes=user_scopes)
            logger.info("... Token authenticated.")
            request.context['user'] = token_info.get('uid')
            request.context['token_info'] = token_info
        return function(request)

    return wrapper
