import server


if not server.DATABASE_URL:
    raise RuntimeError("DATABASE_URL must be configured for the Vercel API function.")
if not server.NEON_AUTH_BASE_URL or not server.NEON_AUTH_JWKS_URL:
    raise RuntimeError("NEON_AUTH_BASE_URL and NEON_AUTH_JWKS_URL must be configured for the Vercel API function.")

server.seed_database()


class handler(server.Handler):
    def _restore_rewritten_path(self):
        self.path = server.restore_vercel_api_path(self.path)

    def do_GET(self):
        self._restore_rewritten_path()
        super().do_GET()

    def do_POST(self):
        self._restore_rewritten_path()
        super().do_POST()

    def do_PUT(self):
        self._restore_rewritten_path()
        super().do_PUT()

    def do_PATCH(self):
        self._restore_rewritten_path()
        super().do_PATCH()

    def do_DELETE(self):
        self._restore_rewritten_path()
        super().do_DELETE()
