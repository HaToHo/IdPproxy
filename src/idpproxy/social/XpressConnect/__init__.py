__author__ = 'haho0032'

import json
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

import xml.etree.ElementTree as ET
from oic.oauth2 import Client
from oic.oauth2.message import ErrorResponse
from oic.oauth2.message import AuthorizationResponse
from idpproxy.social.oauth2 import OAuth2

import logging

logger = logging.getLogger(__name__)


class XpressConnect(OAuth2):
    def __init__(self, client_id, client_secret, **kwargs):
        OAuth2.__init__(self, client_id, client_secret, **kwargs)
        self.token_response_body_type = "json"

 #noinspection PyUnusedLocal
    def phaseN(self, environ, info, server_env, sid):
        session = server_env["CACHE"][sid]

        callback = server_env["base_url"] + self.social_endpoint

        client = Client(client_id=self.client_id,
                        client_authn_method=CLIENT_AUTHN_METHOD)
        response = client.parse_response(AuthorizationResponse, info, "dict")
        logger.info("Response: %s" % response)

        if isinstance(response, ErrorResponse):
            logger.info("%s" % response)
            session["authentication"] = "FAILED"
            return False, "Authentication failed or permission not granted"

        req_args = {
            "redirect_uri": callback,
            "client_secret": self.client_secret,
        }

        client.token_endpoint = self.extra["token_endpoint"]
        tokenresp = client.do_access_token_request(
            scope=self._scope,
            body_type=self.token_response_body_type,
            request_args=req_args,
            authn_method="client_secret_post",
            state=response["state"],
            response_cls=self.access_token_response)

        if isinstance(tokenresp, ErrorResponse):
            logger.info("%s" % tokenresp)
            session["authentication"] = "FAILED"
            return False, "Authentication failed or permission not granted"

        # Download the user profile and cache a local instance of the
        # basic profile info
        result = client.fetch_protected_resource(
            self.userinfo_endpoint(tokenresp), token=tokenresp["access_token"])

        logger.info("Userinfo: %s" % result.text)
        root = ET.fromstring(result.text)
        jsontext = json.dumps(root.attrib)
        profile = json.loads(jsontext)
        profile = self.convert(profile)
        logger.info("PROFILE: %s" % (profile, ))
        session["service"] = self.name
        session["authentication"] = "OK"
        session["status"] = "SUCCESS"
        session["authn_auth"] = self.authenticating_authority
        session["permanent_id"] = profile["uid"]

        server_env["CACHE"][sid] = session

        return True, profile, session