"""Compatibility facade for source-proven registration liveness.

The implementation lives in cohesive source-index, receiver, flow, decorator,
method and patch modules. Existing public and private imports remain available.
"""

from __future__ import annotations
import ast as ast
from pathlib import Path as Path
from typing import Any as Any, Sequence as Sequence
from skylos.deadcode._reachability_bindings import (
    argument_nodes as argument_nodes,
    bound_names as bound_names,
    default_expressions as default_expressions,
)
from skylos.deadcode.python_ast import ParsedPythonFile as ParsedPythonFile
from skylos.visitors.registration_decorators import (
    collect_local_registration_decorators as collect_local_registration_decorators,
)
from skylos.deadcode._registration_common import (
    _FUNCTION_NODES as _FUNCTION_NODES,
    _resolved as _resolved,
    _first_param as _first_param,
    _own_body_nodes as _own_body_nodes,
    _package_base as _package_base,
    _import_aliases as _import_aliases,
    _decorator_reference as _decorator_reference,
    _is_signature_stub as _is_signature_stub,
    _is_static as _is_static,
    _executed_nodes as _executed_nodes,
    _attribute_root as _attribute_root,
)
from skylos.deadcode._registration_decorators import (
    _MAX_ALIAS_HOPS as _MAX_ALIAS_HOPS,
    _module_string_constants as _module_string_constants,
    _key_value as _key_value,
    _tag_keys_on_param as _tag_keys_on_param,
    _tagging_keys as _tagging_keys,
    _collected_keys as _collected_keys,
    find_registered_decorator_targets as find_registered_decorator_targets,
)
from skylos.deadcode._registration_flow import (
    _REGISTRY_CALL_NAMES as _REGISTRY_CALL_NAMES,
    _MAX_FORWARD_DEPTH as _MAX_FORWARD_DEPTH,
    _MethodScope as _MethodScope,
    _wraps_arguments as _wraps_arguments,
    _carries as _carries,
    _RegistrationFlow as _RegistrationFlow,
    _method_index as _method_index,
)
from skylos.deadcode._registration_receivers import (
    _RegistrationReceivers as _RegistrationReceivers,
)
from skylos.deadcode._registration_methods import (
    find_method_registered_targets as find_method_registered_targets,
)
from skylos.deadcode._registration_patches import (
    _external_module_aliases as _external_module_aliases,
    find_patched_instance_methods as find_patched_instance_methods,
)
