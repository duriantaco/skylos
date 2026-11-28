"""Fields and hooks referenced implicitly by proven Python model providers."""

import json
from pathlib import Path
from textwrap import dedent

import pytest

from skylos.analyzer import analyze


def _finding_rows(root, files):
    # The project environment is authoritative even when the scanner itself
    # has Pydantic or pydantic-settings installed.
    (root / ".venv/lib/python3.13/site-packages").mkdir(parents=True)
    for name, source in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(source), encoding="utf-8")
    result = json.loads(
        analyze(str(root), conf=60, grep_verify=False, grep_cache=False)
    )
    return [
        item
        for kind in ("unused_variables", "unused_functions", "unused_classes")
        for item in result.get(kind, ())
    ]


def _findings(root, files):
    return {item["full_name"] for item in _finding_rows(root, files)}


def _findings_by_path(root, files):
    return {
        (
            Path(item["file"]).resolve().relative_to(root.resolve()).as_posix(),
            item["simple_name"],
        )
        for item in _finding_rows(root, files)
    }


def test_pydantic_models_across_relative_imports(tmp_path):
    findings = _findings(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/foundation.py": """
                from pydantic import BaseModel as Provider

                class Foundation(Provider):
                    pass
            """,
            "app/schemas.py": """
                from .foundation import Foundation as Shape
            """,
            "app/main.py": """
                from typing import ClassVar as Metadata
                from pydantic import ConfigDict, RootModel as SequenceModel
                from pydantic import field_validator as validate_field
                from .schemas import Shape as Parent

                class Payload(Parent):
                    title: str
                    revision: int = 1
                    model_config = ConfigDict(extra="forbid")
                    old_limit: Metadata[int] = 3

                    @validate_field("title")
                    @classmethod
                    def validate_title(cls, value):
                        return value.strip()

                    def model_post_init(self, context):
                        pass

                    def forgotten(self):
                        return "unused"

                class Labels(SequenceModel[list[str]]):
                    root: list[str]

                    def model_post_init(self, context):
                        pass

                if __name__ == "__main__":
                    print(Payload(title="hello").model_dump(), Labels(["hello"]))
            """,
        },
    )
    assert findings.isdisjoint(
        {
            "app.main.Payload.title",
            "app.main.Payload.revision",
            "app.main.Payload.model_config",
            "app.main.Payload.model_post_init",
            "app.main.Payload.validate_title",
            "app.main.Labels.root",
            "app.main.Labels.model_post_init",
        }
    )
    assert {"app.main.Payload.old_limit", "app.main.Payload.forgotten"} <= findings


def test_pydantic_settings_and_v1_config_without_provider_source(tmp_path):
    findings = _findings(
        tmp_path,
        {
            "app.py": """
                import pydantic_settings as ps
                from pydantic.v1 import BaseSettings

                class Foundation(ps.BaseSettings):
                    pass

                class Options(Foundation):
                    model_config = ps.SettingsConfigDict(env_prefix="APP_")
                    greeting: str = "hello"

                    @classmethod
                    def settings_customise_sources(cls, settings_cls, init_settings,
                                                   env_settings, dotenv_settings,
                                                   file_secret_settings):
                        return init_settings, env_settings

                    def forgotten(self):
                        return "unused"

                class Legacy(BaseSettings):
                    greeting = "hello"

                    class Config:
                        env_prefix = "LEGACY_"

                        @classmethod
                        def customise_sources(cls, init_settings, env_settings,
                                              file_secret_settings):
                            return init_settings, env_settings

                if __name__ == "__main__":
                    print(Options(), Legacy())
            """
        },
    )
    assert findings.isdisjoint(
        {
            "app.Options.model_config",
            "app.Options.greeting",
            "app.Options.settings_customise_sources",
            "app.Legacy.greeting",
            "app.Legacy.Config",
            "app.Legacy.Config.customise_sources",
        }
    )
    assert "app.Options.forgotten" in findings


def test_local_pydantic_names_do_not_hide_dead_members(tmp_path):
    findings = _findings(
        tmp_path,
        {
            "pydantic.py": """
                class BaseModel:
                    pass

                def field_validator(name):
                    return lambda fn: fn
            """,
            "app.py": """
                from pydantic import BaseModel, field_validator

                class Plain(BaseModel):
                    model_config = {"extra": "forbid"}
                    orphan_field: int = 1

                    @field_validator("orphan_field")
                    def normalize(self, value):
                        return value

                    def model_post_init(self, context):
                        pass

                if __name__ == "__main__":
                    print(Plain())
            """,
        },
    )
    assert {
        "app.Plain.model_config",
        "app.Plain.orphan_field",
        "app.Plain.normalize",
        "app.Plain.model_post_init",
    } <= findings


def test_reassigned_provider_attribute_does_not_establish_a_model(tmp_path):
    findings = _findings(
        tmp_path,
        {
            "app.py": """
                import pydantic as pd

                class Original(pd.BaseModel):
                    live: int

                class Local:
                    pass

                pd.BaseModel = Local

                class Plain(pd.BaseModel):
                    orphaned: int = 1

                if __name__ == "__main__":
                    print(Original(live=3), Plain())
            """
        },
    )
    assert "app.Original.live" not in findings
    assert "app.Plain.orphaned" in findings


def test_sqlmodel_table_and_non_table_descendants(tmp_path):
    findings = _findings(
        tmp_path,
        {
            "app.py": """
                from typing import ClassVar
                import sqlmodel as sm

                class Common(sm.SQLModel):
                    label: str

                class Record(Common, table=True):
                    id: int | None = sm.Field(default=None, primary_key=True)
                    category: str

                class RecordInput(Common):
                    annotation: str
                    old_label: ClassVar[str] = "unused"

                    def forgotten(self):
                        return "unused"

                if __name__ == "__main__":
                    print(Record(label="a", category="x"), RecordInput(label="b", annotation="c"))
            """,
        },
    )
    assert findings.isdisjoint(
        {
            "app.Common.label",
            "app.Record.id",
            "app.Record.category",
            "app.RecordInput.annotation",
        }
    )
    assert {"app.RecordInput.old_label", "app.RecordInput.forgotten"} <= findings


def test_sqlalchemy_implicit_columns_registry_and_mixins(tmp_path):
    findings = _findings(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/base.py": """
                import sqlalchemy.orm as orm

                Catalog = orm.declarative_base()
                mapper = orm.registry()
            """,
            "app/main.py": """
                from typing import ClassVar
                import sqlalchemy.orm as orm
                from sqlalchemy.orm import Mapped as ColumnType
                from .base import Catalog, mapper as mappings

                class Sortable:
                    rank: ColumnType[int]
                    old_limit: ClassVar[int] = 3

                    @orm.declared_attr
                    @classmethod
                    def rank_hint(cls) -> ColumnType[int]:
                        return orm.column_property(1)

                    def forgotten(self):
                        return "unused"

                class Product(Sortable, Catalog):
                    __tablename__ = "product"
                    id: ColumnType[int] = orm.mapped_column(primary_key=True)
                    title: orm.Mapped[str]

                @mappings.mapped
                class Archive:
                    __tablename__ = "archive"
                    id: ColumnType[int] = orm.mapped_column(primary_key=True)
                    description: ColumnType[str]

                local_mappings = orm.registry()

                @local_mappings.mapped_as_dataclass
                class Snapshot:
                    __tablename__ = "snapshot"
                    id: ColumnType[int] = orm.mapped_column(primary_key=True)
                    source_name: ColumnType[str]

                class Unmapped:
                    annotated_but_not_mapped: ColumnType[int]
                    old_flag = True

                if __name__ == "__main__":
                    print(Product(), Archive(), Snapshot(1, "example"), Unmapped())
            """,
        },
    )
    assert findings.isdisjoint(
        {
            "app.main.Sortable.rank",
            "app.main.Sortable.rank_hint",
            "app.main.Product.id",
            "app.main.Product.title",
            "app.main.Archive.id",
            "app.main.Archive.description",
            "app.main.Snapshot.source_name",
        }
    )
    assert {
        "app.main.Sortable.old_limit",
        "app.main.Sortable.forgotten",
        "app.main.Unmapped.annotated_but_not_mapped",
        "app.main.Unmapped.old_flag",
    } <= findings


def test_local_orm_names_do_not_hide_dead_members(tmp_path):
    findings = _findings(
        tmp_path,
        {
            "app.py": """
                from typing import Generic, TypeVar

                T = TypeVar("T")

                class Mapped(Generic[T]):
                    pass

                class Base:
                    pass

                def mapped_column():
                    return 1

                class Ordinary(Base):
                    orphan_attribute: Mapped[int]
                    orphan_call = mapped_column()

                if __name__ == "__main__":
                    print(Ordinary())
            """,
        },
    )
    assert {"app.Ordinary.orphan_attribute", "app.Ordinary.orphan_call"} <= findings


@pytest.mark.parametrize(
    "provider,members",
    [
        ("from pydantic import BaseModel as Provider", "    title: str\n"),
        (
            "from sqlalchemy.orm import DeclarativeBase as Provider",
            (
                '    __tablename__ = "record"\n'
                "    identifier: Mapped[int] = mapped_column(primary_key=True)\n"
                "    title: Mapped[str]\n"
            ),
        ),
    ],
)
def test_model_imports_respect_nested_projects(tmp_path, provider, members):
    consumer = (
        "from sqlalchemy.orm import Mapped, mapped_column\n"
        "from api.model_base import Foundation as Parent\n\n"
        "class Record(Parent):\n" + members + "\n"
        "if __name__ == '__main__':\n    print(Record(title='ready'))\n"
    )
    plain = "class Foundation:\n    def __init__(self, **values):\n        pass\n"
    files = {
        "api/__init__.py": "",
        "api/model_base.py": plain,
    }
    for project, base in (
        ("service", provider + "\n\nclass Foundation(Provider):\n    pass\n"),
        ("tools", plain),
    ):
        files[f"{project}/pyproject.toml"] = f'[project]\nname = "{project}"\n'
        files[f"{project}/src/api/__init__.py"] = ""
        files[f"{project}/src/api/model_base.py"] = base
        files[f"{project}/src/api/models.py"] = (
            consumer
            if project == "service"
            else consumer.replace("Record", "Ordinary")
            .replace("title", "orphan_title")
            .replace("identifier", "orphan_identifier")
        )
    findings = _findings_by_path(tmp_path, files)
    assert ("service/src/api/models.py", "title") not in findings
    assert ("tools/src/api/models.py", "orphan_title") in findings
    if "sqlalchemy" in provider:
        assert ("service/src/api/models.py", "identifier") not in findings
        assert ("tools/src/api/models.py", "orphan_identifier") in findings


def test_nested_project_provider_shadowing_is_local(tmp_path):
    consumer = """
        from pydantic import BaseModel

        class Record(BaseModel):
            title: str = "ready"

        if __name__ == "__main__":
            print(Record())
    """
    files = {"tools/src/pydantic.py": "class BaseModel:\n    pass\n"}
    for project in ("service", "tools"):
        files[f"{project}/pyproject.toml"] = f'[project]\nname = "{project}"\n'
        files[f"{project}/src/api/__init__.py"] = ""
        files[f"{project}/src/api/models.py"] = (
            consumer
            if project == "service"
            else consumer.replace("Record", "Ordinary").replace("title", "orphan_title")
        )
    findings = _findings_by_path(tmp_path, files)
    assert ("tools/src/api/models.py", "orphan_title") in findings
    assert ("service/src/api/models.py", "title") not in findings
