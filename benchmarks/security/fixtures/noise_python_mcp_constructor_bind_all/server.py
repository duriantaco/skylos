from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Tools", host="0.0.0.0", port=3005)


@mcp.tool()
def ping() -> str:
    return "pong"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
