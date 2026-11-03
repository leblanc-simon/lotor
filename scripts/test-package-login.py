#!/usr/bin/env python3
"""Première connexion réelle à travers le mandataire : mot de passe temporaire, enrôlement
du TOTP, codes de secours, nouveau mot de passe. Lancé dans le conteneur de recette du
paquet, sans dépendance (scripts/test-package.sh)."""
import base64
import hashlib
import hmac
import http.cookiejar
import re
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NEW_PASSWORD = "lotor-recette-paquet-2026"


def totp(secret):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return "%06d" % ((struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1000000)


def main(base, email, password):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(jar)
    )

    def fetch(path, form=None):
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        try:
            with opener.open(base + path, data, timeout=30) as response:
                return urllib.parse.urlparse(response.url).path, response.read().decode()
        except urllib.error.HTTPError as err:
            sys.exit("%s : HTTP %d\n%s" % (path, err.code, err.read().decode()[:500]))

    def token(page):
        found = re.search(r'name="csrf_token" value="([^"]+)"', page)
        if not found:
            sys.exit("jeton CSRF absent :\n" + page[:500])
        return found.group(1)

    _, page = fetch("/login")
    where, page = fetch("/login", {"csrf_token": token(page), "email": email, "password": password})
    if where != "/account/totp/setup":
        sys.exit("après la connexion, attendu l'enrôlement du TOTP, obtenu " + where)
    if not any(c.name == "__Host-lotor_session" and c.secure for c in jar):
        sys.exit("cookie de session __Host- sécurisé absent : " + ", ".join(c.name for c in jar))

    secret = re.search(r'class="auth__secret">([^<]+)<', page)
    if not secret:
        sys.exit("secret TOTP absent :\n" + page[:500])
    code = totp(re.sub(r"\s", "", secret.group(1)))
    where, page = fetch("/account/totp/enable", {"csrf_token": token(page), "code": code})
    following = re.search(r'class="btn btn--primary" href="([^"]+)"', page)
    if not following:
        sys.exit("codes de secours absents (%s) :\n%s" % (where, page[:500]))

    where, page = fetch(following.group(1))
    if where != "/account/password":
        sys.exit("attendu le changement de mot de passe, obtenu " + where)
    where, page = fetch(
        "/account/password",
        {"csrf_token": token(page), "current": password, "password": NEW_PASSWORD, "confirm": NEW_PASSWORD},
    )
    where, _ = fetch("/")
    if where in ("/login", "/account/password", "/account/totp/setup"):
        sys.exit("parcours inachevé : renvoyé vers " + where)
    print("première connexion complète")


if __name__ == "__main__":
    main(*sys.argv[1:4])
