import typer

app = typer.Typer()


@app.callback()
def main(verbose: bool = False):
    return verbose
