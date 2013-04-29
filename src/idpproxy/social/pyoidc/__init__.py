__author__ = 'haho0032'

from idpproxy.social.oauth2 import OAuth2

import logging

logger = logging.getLogger(__name__)


class pyoidcOAuth2(OAuth2):
    def __init__(self, client_id, client_secret, **kwargs):
        OAuth2.__init__(self, client_id, client_secret, **kwargs)
        self.token_response_body_type = "json"

