from flask import Flask, url_for, session, redirect, request, render_template
from dotenv import load_dotenv
import globus_sdk
from globus_sdk.scopes import GCSCollectionScopeBuilder, TransferScopes
import os

load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = 'very secret!'
# app.config.from_pyfile("example_app.conf")


# actually run the app if this is called as a script
if __name__ == "__main__":
    app.run()


def load_app_client():
    return globus_sdk.ConfidentialAppAuthClient(
        os.environ.get("GLOBUS_CLIENT_ID"),
        os.environ.get("GLOBUS_CLIENT_SECRET")
    )


@app.route("/")
def index():
    """
    This could be any page you like, rendered by Flask.
    For this simple example, it will either redirect you to login, or print
    a simple message.
    """
    # session.clear()
    if not session.get("is_authenticated"):
        return redirect(url_for("login"))
    # return redirect(url_for("logout"))
    return "You are successfully logged in!"


@app.route("/user")
def user():
    print(session)
    authorizer = globus_sdk.AccessTokenAuthorizer(
        session["tokens"]["transfer.api.globus.org"]["access_token"]
    )
    transfer_client = globus_sdk.TransferClient(authorizer=authorizer)

    print("Endpoints belonging to the current logged-in user:")
    test_user = []
    test_user.append("[201192ac-9f4b-11e9-821b-02b7a92d8e58] The Jackson Laboratory Scientific Services")
    test_user.append("[b8377de1-47c2-11e7-bd5c-22000b9a448b] The Jackson Laboratory for Genomic Medicine")
    for ep in transfer_client.endpoint_search(filter_scope="my-endpoints"):
        test_user.append("[{}] {}".format(ep["id"], ep["display_name"]))
    collection_id = '201192ac-9f4b-11e9-821b-02b7a92d8e58'
    collection_path = "/globus/microscopy_delivery/bh-microscopy/"
    response = transfer_client.operation_ls(collection_id, path=collection_path)
    test_user.append(f"==== 'ls' for {collection_path} on collection {collection_id} ====")
    for item in response:
        test_user.append(f"{item['type']}: {item['name']} [{item['size']}]")
    return test_user


@app.route("/login")
def login():
    """
    Login via Globus Auth.
    May be invoked in one of two scenarios:

      1. Login is starting, no state in Globus Auth yet
      2. Returning to application during login, already have short-lived
         code from Globus Auth to exchange for tokens, encoded in a query
         param
    """
    # the redirect URI, as a complete URI (not relative path)

    redirect_uri = url_for("login", _external=True)
    transfer_scope = TransferScopes.make_mutable("all")
    MAPPED_COLLECTION_ID = '201192ac-9f4b-11e9-821b-02b7a92d8e58'
    data_access_scope = GCSCollectionScopeBuilder(MAPPED_COLLECTION_ID).make_mutable(
        "data_access", optional=True
    )
    # add data_access as a dependency
    transfer_scope.add_dependency(data_access_scope)
    client = load_app_client()
    client.oauth2_start_flow(redirect_uri, requested_scopes=transfer_scope)

    # If there's no "code" query string parameter, we're in this route
    # starting a Globus Auth login flow.
    # Redirect out to Globus Auth
    if "code" not in request.args:
        auth_uri = client.oauth2_get_authorize_url()
        return redirect(auth_uri)
    # If we do have a "code" param, we're coming back from Globus Auth
    # and can start the process of exchanging an auth code for a token.
    else:
        code = request.args.get("code")
        print(code)
        tokens = client.oauth2_exchange_code_for_tokens(code)
        print(tokens)
        # store the resulting tokens in the session
        session.update(tokens=tokens.by_resource_server, is_authenticated=True)
        print("session updated")
        return redirect(url_for("index"))


@app.route("/logout")
def logout():
    """
    - Revoke the tokens with Globus Auth.
    - Destroy the session state.
    - Redirect the user to the Globus Auth logout page.
    """
    client = load_app_client()

    # Revoke the tokens with Globus Auth
    for token in (
        token_info["access_token"] for token_info in session["tokens"].values()
    ):
        client.oauth2_revoke_token(token)

    # Destroy the session state
    session.clear()

    # the return redirection location to give to Globus AUth
    redirect_uri = url_for("index", _external=True)

    # build the logout URI with query params
    # there is no tool to help build this (yet!)
    globus_logout_url = (
        "https://auth.globus.org/v2/web/logout"
        + "?client={}".format(os.environ.get("GLOBUS_CLIENT_ID"))
        + "&redirect_uri={}".format(redirect_uri)
        + "&redirect_name=Globus Example App"
    )

    # Redirect the user to the Globus Auth logout page
    return redirect(globus_logout_url)



# authorizer = globus_sdk.AccessTokenAuthorizer(
#     session["tokens"]["transfer.api.globus.org"]["access_token"]
# )
# transfer_client = globus_sdk.TransferClient(authorizer=authorizer)

# print("Endpoints belonging to the current logged-in user:")
# for ep in transfer_client.endpoint_search(filter_scope="my-endpoints"):
#     print("[{}] {}".format(ep["id"], ep["display_name"]))