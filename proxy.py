from vercel.proxy import Proxy, Request, Response, RewriteResponse

proxy = Proxy()


@proxy.route("/api/{path:path}")
def route_api(request: Request) -> Response:
    original_path = request.url.path
    if request.url.query:
        original_path += "?" + request.url.query
    return RewriteResponse(
        "/api/router",
        request_headers={"x-nuu-original-path": original_path},
    )
