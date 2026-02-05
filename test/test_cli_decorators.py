import ast
from skylos.visitors.framework_aware import FrameworkAwareVisitor


class TestCLIDecoratorDetection:

    def test_cyclopts_app_command(self):
        code = '''
import cyclopts
app = cyclopts.App()

@app.command
def greet(name: str):
    print(f"Hello {name}")
'''
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        visitor.finalize()
        
        assert visitor.is_framework_file
        assert 6 in visitor.framework_decorated_lines

    def test_cyclopts_app_default(self):
        code = '''
import cyclopts
app = cyclopts.App()

@app.default
def main():
    print("Default command")
'''
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        visitor.finalize()
        
        assert visitor.is_framework_file
        # def main line
        assert 6 in visitor.framework_decorated_lines

    def test_typer_app_command(self):
        """@app.command should work for typer too."""
        code = '''
import typer
app = typer.Typer()

@app.command()
def hello(name: str):
    typer.echo(f"Hello {name}")
'''
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        visitor.finalize()
        
        assert visitor.is_framework_file
        # def hello line
        assert 6 in visitor.framework_decorated_lines

    def test_click_command(self):
        """@cli.command should work for click."""
        code = '''
import click

@click.group()
def cli():
    pass

@cli.command()
def init():
    click.echo("Initialized")
'''
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        visitor.finalize()
        
        assert visitor.is_framework_file
        assert 5 in visitor.framework_decorated_lines
          # def init line
        assert 9 in visitor.framework_decorated_lines

    def test_app_callback(self):
        code = '''
import typer
app = typer.Typer()

@app.callback()
def main(verbose: bool = False):
    pass
'''
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        visitor.finalize()
        
        assert 6 in visitor.framework_decorated_lines

    def test_generic_command_decorator(self):
        code = '''
@cli.command
def foo():
    pass

@main.command()
def bar():
    pass

@something.subcommand
def baz():
    pass
'''
        tree = ast.parse(code)
        visitor = FrameworkAwareVisitor()
        visitor.visit(tree)
        visitor.finalize()
        
        assert 3 in visitor.framework_decorated_lines
        assert 7 in visitor.framework_decorated_lines
        assert 11 in visitor.framework_decorated_lines