from urllib.parse import parse_qsl, urlencode, urlsplit

import server


if not server.DATABASE_URL:
    raise RuntimeError("DATABASE_URL must be configured for the Vercel API function.")

server.seed_database()


class handler(server.Handler):
    def parse_request(self):
        if not super().parse_request():
            return False
        parsed=urlsplit(self.path)
        params=parse_qsl(parsed.query,keep_blank_values=True)
        forwarded_path=next((value for key,value in params if key=="__vercel_path"),None)
        if forwarded_path is not None:
            route="/"+forwarded_path.lstrip("/")
            remaining=urlencode([(key,value) for key,value in params if key!="__vercel_path"],doseq=True)
            self.path="/api"+route+("?"+remaining if remaining else "")
        return True
