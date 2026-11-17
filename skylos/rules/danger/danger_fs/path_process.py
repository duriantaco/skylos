"""Static argument edges across narrowly identified Python subprocesses.

The records add possible data-flow edges; their absence never proves that a
script is operator-only. Relative script names are project-local candidates,
not a proof of the process's working directory. No scanned code is executed.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from skylos.rules.danger.import_proof import provider_binding_is_stable

if TYPE_CHECKING:
    from .path_provenance import _Project, _Scope, _Unit


_LAUNCHERS = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
    }
)
_MAX_LAUNCHES = 4096
_MAX_CONTEXT_WORK = 100000
_UNMAPPED_LAUNCHERS = frozenset(
    {
        "os.system",
        "os.popen",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.execl",
        "os.execlp",
        "os.spawnv",
        "os.spawnl",
        "os.spawnvp",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
    }
)


@dataclass(frozen=True)
class PythonArgSource:
    unit: _Unit
    scope: _Scope
    call: ast.Call
    argument: ast.expr
    argv_index: int
    command_index: int
    script_path: Path
    exact_target: bool


@dataclass(frozen=True)
class PythonArgUncertainty:
    unit: _Unit
    scope: _Scope
    call: ast.Call
    script_path: Path
    reason: str


@dataclass(frozen=True)
class PythonArgLaunch:
    unit: _Unit
    scope: _Scope
    call: ast.Call
    command: ast.expr
    argv: tuple[ast.expr, ...]
    script_path: Path | None
    exact_target: bool
    uncertainty: str | None


def _external_name(
    project: _Project, unit: _Unit, scope: _Scope, node: ast.expr, *, stable=False
):
    values = project.values(unit, scope, node)
    if not values or len(values) != 1:
        return None
    value = next(iter(values))
    if value.kind != "ext":
        return None
    if stable and not provider_binding_is_stable(
        value.name, unit.tree, unit.path, project.root
    ):
        return None
    return value.name


def _literal_string(node):
    return (
        node.value
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        else None
    )


def _target_paths(project: _Project, unit: _Unit, script: str, cwd):
    target = Path(script)
    directory = _literal_string(cwd)
    exact = target.is_absolute()
    if target.is_absolute():
        candidates = [target]
    elif directory is not None and Path(directory).is_absolute():
        exact = True
        candidates = [Path(directory) / target]
    else:
        relative = Path(directory) / target if directory is not None else target
        candidates = [project.root / relative, unit.path.parent / relative]
        if ".." not in relative.parts:
            # The launcher's cwd is not known. Keep every indexed child with
            # the same lexical suffix, without claiming cwd equals scan root.
            candidates.extend(
                path
                for path in project.by_path
                if path.parts[-len(relative.parts) :] == relative.parts
            )
    root = project.root.resolve()
    paths = {}
    for path in candidates:
        try:
            path = path.resolve()
            path.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            continue
        if path in project.by_path and path not in paths:
            paths[path] = (exact, None)
        entry = path / "__main__.py"
        if entry in project.by_path and entry not in paths:
            paths[entry] = (exact, None)
    if (
        directory is not None
        and not Path(directory).is_absolute()
        and target.parts
        and ".." not in target.parts
    ):
        # A literal relative cwd is relative to the parent's runtime cwd,
        # which is not proved by the scan root. Preserve other indexed child
        # candidates as unresolved context, without inventing an exact edge.
        for path in project.by_path:
            if path not in paths and path.parts[-len(target.parts) :] == target.parts:
                paths[path] = (
                    False,
                    "the relative process working directory does not establish this child context",
                )
    return tuple((path, exact, reason) for path, (exact, reason) in paths.items())


def _launch_index(project: _Project):
    cached = getattr(project, "_python_process_launch_index", None)
    if cached is not None:
        return cached
    index: dict[Path, list[PythonArgLaunch]] = {}
    ambiguous = []
    target_paths = {}
    launches = 0
    for unit in project.units:
        for call, scope in unit.calls:
            values = project.values(unit, scope, call.func)
            names = {
                value.name
                for value in values or ()
                if value.kind == "ext"
                and value.name in _LAUNCHERS | _UNMAPPED_LAUNCHERS
            }
            if not names:
                continue
            launches += 1
            if launches > _MAX_LAUNCHES:
                # A partial launch index is not a sound argument proof. The
                # resolver's exception boundary retains INCOMPLETE findings.
                raise ValueError("Python process launch index budget reached")
            keywords = {keyword.arg: keyword.value for keyword in call.keywords}
            if call.args and "args" in keywords:
                continue
            command = call.args[0] if call.args else keywords.get("args")
            if command is None and call.keywords:
                command = call.keywords[0].value
            if command is None:
                continue
            if names & _UNMAPPED_LAUNCHERS:
                ambiguous.append(
                    PythonArgLaunch(
                        unit,
                        scope,
                        call,
                        command,
                        (),
                        None,
                        False,
                        "this process transport has no proven Python argv mapping",
                    )
                )
                continue
            native_provider = len(values) == 1 and all(
                provider_binding_is_stable(name, unit.tree, unit.path, project.root)
                for name in names
            )
            if not isinstance(command, (ast.List, ast.Tuple)) or len(command.elts) < 2:
                ambiguous.append(
                    PythonArgLaunch(
                        unit,
                        scope,
                        call,
                        command,
                        (),
                        None,
                        False,
                        "the process command does not establish a child Python script",
                    )
                )
                continue
            if (
                _external_name(project, unit, scope, command.elts[0], stable=True)
                != "sys.executable"
            ):
                ambiguous.append(
                    PythonArgLaunch(
                        unit,
                        scope,
                        call,
                        command,
                        (),
                        None,
                        False,
                        "the process interpreter does not establish Python argv binding",
                    )
                )
                continue
            script = _literal_string(command.elts[1])
            if not script or script.startswith("-"):
                ambiguous.append(
                    PythonArgLaunch(
                        unit,
                        scope,
                        call,
                        command,
                        (),
                        None,
                        False,
                        "the process script target is not a fixed Python source path",
                    )
                )
                continue
            uncertainty = None
            if not native_provider:
                uncertainty = (
                    "the process provider may be modified or have mixed targets"
                )
            if any(isinstance(argument, ast.Starred) for argument in command.elts):
                uncertainty = (
                    "starred process arguments do not establish fixed argv positions"
                )
            if None in keywords:
                uncertainty = (
                    "unpacked process options may change execution or argv binding"
                )
            shell = keywords.get("shell")
            if shell is not None and not (
                isinstance(shell, ast.Constant) and shell.value is False
            ):
                uncertainty = "shell execution does not establish Python argv binding"
            if "executable" in keywords:
                uncertainty = (
                    "an overridden executable does not establish Python argv binding"
                )
            environment = keywords.get("env")
            if environment is not None and not (
                isinstance(environment, ast.Constant) and environment.value is None
            ):
                uncertainty = (
                    "a custom process environment may alter Python startup or argv"
                )
            cwd = keywords.get("cwd")
            if (
                cwd is not None
                and not (isinstance(cwd, ast.Constant) and cwd.value is None)
                and _literal_string(cwd) is None
            ):
                uncertainty = "a dynamic process working directory leaves the child context unresolved"
            target_key = (unit.path.parent, script, _literal_string(cwd))
            if target_key not in target_paths:
                target_paths[target_key] = _target_paths(project, unit, script, cwd)
            if not target_paths[target_key]:
                ambiguous.append(
                    PythonArgLaunch(
                        unit,
                        scope,
                        call,
                        command,
                        tuple(command.elts[1:]),
                        None,
                        False,
                        "the process target is outside the indexed Python sources",
                    )
                )
            for path, exact, target_uncertainty in target_paths[target_key]:
                index.setdefault(path, []).append(
                    PythonArgLaunch(
                        unit,
                        scope,
                        call,
                        command,
                        tuple(command.elts[1:]),
                        path,
                        exact,
                        uncertainty or target_uncertainty,
                    )
                )
    # Publish only a completed index: a resolution exception must not leave
    # earlier launches cached as an exhaustive set.
    cached = ({path: tuple(values) for path, values in index.items()}, tuple(ambiguous))
    project._python_process_launch_index = cached
    return cached


def python_argv_sources(
    project: _Project, child_unit: _Unit, index: int
) -> tuple[PythonArgSource, ...]:
    """Possible parent expressions bound to a child's fixed ``sys.argv`` index.

    These records never establish that every launch is known or that the
    argument is safe. Trace each expression in its original parent scope.
    """
    if isinstance(index, bool) or not isinstance(index, int):
        return ()
    sources = []
    for launch in python_argv_launches(project, child_unit):
        if launch.uncertainty:
            continue
        position = index if index >= 0 else len(launch.argv) + index
        if not 0 <= position < len(launch.argv):
            continue
        sources.append(
            PythonArgSource(
                launch.unit,
                launch.scope,
                launch.call,
                launch.argv[position],
                index,
                position + 1,
                launch.script_path,
                launch.exact_target,
            )
        )
    return tuple(sources)


def python_argv_uncertainties(
    project: _Project, child_unit: _Unit
) -> tuple[PythonArgUncertainty, ...]:
    """Known child candidates whose launch options prevent argument mapping."""
    return tuple(
        PythonArgUncertainty(
            launch.unit,
            launch.scope,
            launch.call,
            launch.script_path,
            launch.uncertainty,
        )
        for launch in python_argv_launches(project, child_unit)
        if launch.uncertainty
    )


def python_argv_launches(
    project: _Project, child_unit: _Unit
) -> tuple[PythonArgLaunch, ...]:
    """Project launches that can identify this child, including uncertain ones."""
    return _launch_index(project)[0].get(child_unit.path, ())


def python_argv_ambiguous_launches(project: _Project) -> tuple[PythonArgLaunch, ...]:
    """Launches whose target cannot be related to one particular child."""
    return _launch_index(project)[1]


def _process_context_index(project: _Project):
    """Map source units to launched entries that may load them, directionally."""
    cached = getattr(project, "_python_process_context_index", None)
    if cached is not None:
        return cached
    failure = getattr(project, "_python_process_context_failure", None)
    if failure:
        raise ValueError(failure)

    from .path_provenance import _IMPLICIT_MODULES

    launches_by_entry = _launch_index(project)[0]
    startup = tuple(
        unit for unit in project.units if unit.path.stem in _IMPLICIT_MODULES
    )
    index = {}
    work = 0

    def charge():
        nonlocal work
        work += 1
        if work > _MAX_CONTEXT_WORK:
            message = "Python process import context budget reached"
            project._python_process_context_failure = message
            raise ValueError(message)

    def closure(roots):
        found = {}
        pending = list(roots)
        dynamic = False
        while pending:
            unit = pending.pop()
            if id(unit) in found:
                continue
            charge()
            found[id(unit)] = unit
            dynamic |= project._loads_dynamically(unit)
            for child in project.imported_units(unit):
                charge()
                if id(child) not in found:
                    pending.append(child)
        return found, dynamic

    startup_units, startup_dynamic = closure(startup)
    identities = {}
    for entry_path in sorted(launches_by_entry, key=str):
        entry = project.by_path.get(entry_path)
        if entry is None:
            raise ValueError("launched Python entry is absent from the project index")
        imported, dynamic = closure((entry,))
        members = dict(startup_units)
        members.update(imported)
        dynamic |= startup_dynamic
        if dynamic:
            members.update((id(unit), unit) for unit in project.units)
        for source in sorted(members.values(), key=lambda unit: unit.rel):
            if dynamic:
                reason = "the runtime import context contains a dynamic loader"
            elif id(source) not in imported:
                reason = (
                    "the implicit startup import context is not a fixed entry import"
                )
            else:
                reason = None
            for launch in launches_by_entry[entry_path]:
                charge()
                candidate = (
                    replace(launch, uncertainty=launch.uncertainty or reason)
                    if reason
                    else launch
                )
                values = index.setdefault(source.path, [])
                seen = identities.setdefault(source.path, set())
                identity = (
                    id(candidate.call),
                    candidate.script_path,
                    candidate.uncertainty,
                )
                if identity not in seen:
                    seen.add(identity)
                    values.append(candidate)
    # Only a completed directed context index can answer a negative query.
    cached = {path: tuple(values) for path, values in index.items()}
    project._python_process_context_index = cached
    return cached


def python_process_context_launches(
    project: _Project, origin_unit: _Unit
) -> tuple[PythonArgLaunch, ...]:
    """Launches whose entry may load this source in its directed import closure.

    Importers are never walked backwards: two unrelated scripts importing the
    same utility do not thereby become one process. Context candidates support
    uncertainty review, not exact argv binding in an imported source module.
    """
    return _process_context_index(project).get(origin_unit.path, ())
