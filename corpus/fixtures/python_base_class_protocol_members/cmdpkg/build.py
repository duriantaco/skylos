def build_cmdclass():
    from setuptools import Command

    class cmd_report(Command):
        description = "report"
        user_options: list[tuple[str, str, str]] = []
        boolean_options: list[str] = []
        scratch_values: list[str] = []

        def initialize_options(self) -> None:
            pass

        def finalize_options(self) -> None:
            pass

        def run(self) -> None:
            print("report")

    return {"report": cmd_report}


print(build_cmdclass())
