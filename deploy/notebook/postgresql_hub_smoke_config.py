"""Disposable JupyterHub startup fixture used by image qualification only."""

from jupyterhub.auth import DummyAuthenticator
from jupyterhub.proxy import Proxy


class QualificationProxy(Proxy):
    """Keep the qualification focused on Hub/ORM startup, not public ingress."""

    should_start = False

    async def start(self):
        return None

    async def get_all_routes(self):
        return {}

    async def add_route(self, routespec, target, data):
        return None

    async def delete_route(self, routespec):
        return None


c = get_config()  # noqa: F821 - provided by JupyterHub's config loader
c.JupyterHub.authenticator_class = DummyAuthenticator
c.JupyterHub.proxy_class = QualificationProxy
c.JupyterHub.bind_url = "http://127.0.0.1:18000"
c.JupyterHub.hub_bind_url = "http://127.0.0.1:18081"
c.JupyterHub.cookie_secret = bytes.fromhex("11" * 32)
c.JupyterHub.cleanup_servers = False
c.JupyterHub.cleanup_proxy = False
c.JupyterHub.allow_named_servers = False
