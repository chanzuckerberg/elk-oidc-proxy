import base64
import functools
import json
import os
import sys
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from urllib.parse import urlencode

import boto3
import jwt
import logging
from botocore.vendored import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from requests_aws4auth import AWS4Auth
from flask import Flask, make_response, request

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler(stream=sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

app = Flask('elk-oidc-proxy')

sts = boto3.client("sts")

PUBLIC_KEY_CACHE = dict()
PUBLIC_KEY_TTL = timedelta(hours=1)


def get_openid_config(openid_provider):
    res = requests.get(f"https://{openid_provider}/.well-known/openid-configuration")
    res.raise_for_status()
    return res.json()


def fetch_public_keys(openid_provider):
    return requests.get(get_openid_config(openid_provider)["jwks_uri"]).json()["keys"]


def refresh_public_key_cache(keys):
    global PUBLIC_KEY_CACHE
    # clear old cache items
    for kid, tup in PUBLIC_KEY_CACHE.items():
        key, expiry = tup
        if expiry >= datetime.utcnow():
            del PUBLIC_KEY_CACHE[kid]
    # add new keys
    expiry = datetime.utcnow() + PUBLIC_KEY_TTL
    for key in keys:
        PUBLIC_KEY_CACHE[key['kid']] = [
            rsa.RSAPublicNumbers(
                e=int.from_bytes(base64.urlsafe_b64decode(key["e"] + "==="), byteorder="big"),
                n=int.from_bytes(base64.urlsafe_b64decode(key["n"] + "==="), byteorder="big")
            ).public_key(backend=default_backend()),
            expiry
        ]


def get_public_key(kid):
    if kid not in PUBLIC_KEY_CACHE:
        refresh_public_key_cache(fetch_public_keys(os.environ["OPENID_PROVIDER"]))
    key, _ = PUBLIC_KEY_CACHE[kid]
    return key


def get_redirect_uri():
    return "https://{}/oauth2/callback".format(os.environ['PROXY_FQDN'])


@app.route("/oauth2/callback", methods=["GET"])
def oauth2_callback():
    state = json.loads(base64.b64decode(request.args["state"]))
    token_endpoint = get_openid_config(os.environ["OPENID_PROVIDER"])["token_endpoint"]
    res = requests.post(token_endpoint, dict(code=request.args["code"],
                                             client_id=os.environ["OAUTH2_CLIENT_ID"],
                                             client_secret=os.environ["OAUTH2_CLIENT_SECRET"],
                                             redirect_uri=get_redirect_uri(),
                                             grant_type="authorization_code"))
    token_header = jwt.get_unverified_header(res.json()["id_token"])
    tok = jwt.decode(res.json()["id_token"],
                     key=get_public_key(token_header["kid"]),
                     audience=os.environ["OAUTH2_CLIENT_ID"])
    assert tok["email_verified"]
    credentials = sts.assume_role(RoleArn=os.environ["ASSUME_ROLE_ARN"], RoleSessionName=tok["email"])["Credentials"]
    del credentials["Expiration"]
    cookie = base64.b64encode(json.dumps(credentials).encode()).decode()
    cookie_header = "elk_auth={}; Path=/; Max-Age=3600; Secure; HttpOnly".format(cookie)
    response = make_response("", 302)
    response.headers['Location'] = state["nav_origin"]
    response.headers['Set-Cookie'] = cookie_header
    return response


@app.route("/-/health")
def health():
    status = {
        'operation': 'healthcheck',
        'body': 'NOT OK',
        'status_code': 500
    }
    try:
        credentials = sts.assume_role(
            RoleArn=os.environ["ASSUME_ROLE_ARN"],
            RoleSessionName=os.environ['HEALTHCHECK_ACCOUNT_EMAIL']
        )["Credentials"]
        es_auth = aws4_auth(credentials)
        proxy_res = requests.request(method='GET', url=os.environ['ES_ENDPOINT'], auth=es_auth)
        status['es_response'] = proxy_res.status_code
        if proxy_res.status_code == 200:
            status['body'] = 'OK'
            status['status_code'] = 200
    except Exception as e:
        status['error'] = str(e)
    response = make_response(status['body'], status['status_code'])
    logger.info(json.dumps(status))
    return response


@app.route("/", defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def index(path):
    cookies = SimpleCookie(request.headers.get("cookie"))
    if "elk_auth" not in cookies:
        cur_loc = "https://{}/{}".format(os.environ['PROXY_FQDN'], path)
        state = base64.b64encode(json.dumps({"nav_origin": cur_loc}).encode())
        oauth2_params = dict(client_id=os.environ["OAUTH2_CLIENT_ID"],
                             response_type="code",
                             scope="openid email profile",
                             redirect_uri=get_redirect_uri(),
                             state=state)
        dest = get_openid_config(os.environ["OPENID_PROVIDER"])["authorization_endpoint"]
        dest = dest + "?" + urlencode(oauth2_params)
        status_code = 302
        response = make_response("", status_code)
        response.headers['Location'] = dest
        logger.info(json.dumps({'status_code': status_code, 'destination': dest, 'source': cur_loc}))
        return response
    credentials = json.loads(base64.b64decode(cookies["elk_auth"].value))
    es_auth = aws4_auth(credentials)
    dest_url = os.environ["ES_ENDPOINT"] + request.path
    if len(request.args) > 0:
        dest_url = dest_url + "?" + urlencode(request.args)

    # build request headers and make request
    request_headers = dict()
    if 'Content-Type' in request.headers:
        request_headers['Content-Type'] = request.headers['Content-Type']
    if 'Kbn-Version' in request.headers:
        request_headers['Kbn-Version'] = request.headers['Kbn-Version']

    proxy_res = requests.request(method=request.method, url=dest_url, auth=es_auth, headers=request_headers, data=request.data)

    # build response headers and body
    response_headers = {"Content-Type": proxy_res.headers["Content-Type"]} if 'Content-Type' in proxy_res.headers else dict()
    if proxy_res.headers.get('Content-Type', '').startswith("application/json"):
        body = json.dumps(proxy_res.json())
    else:
        body = proxy_res.content

    response = make_response(body, proxy_res.status_code)
    response.headers = response_headers
    if 200 <= proxy_res.status_code < 400:
        logger.info(json.dumps({'status_code': proxy_res.status_code, 'destination': dest_url}))
    else:
        logger.error(json.dumps({
            'status_code': proxy_res.status_code,
            'destination': dest_url,
            'request_method': request.method,
            'request_headers': request_headers,
            'request_body': request.data,
            'response_body': str(proxy_res.content)
        }))
    return response


def aws4_auth(credentials):
    return AWS4Auth(
        credentials["AccessKeyId"],
        credentials["SecretAccessKey"],
        "us-east-1",
        "es",
        session_token=credentials["SessionToken"]
    )


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get('PORT', '5000')))
