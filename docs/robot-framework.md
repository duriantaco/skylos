# Robot Framework dead-code analysis

Skylos reads `Library` and `Variables` settings in `.robot` files without
importing Robot Framework or executing the imported Python code. It also follows
`Resource` settings into `.robot` and `.resource` files. An unimported
`.resource` file does not activate its libraries.

```robotframework
*** Settings ***
Library      libraries/Actions.py    AS    Actions
Variables    data/values.py
Resource     resources/common.resource
```

For a class library, the selected class and its public keyword methods become
entrypoints. For a module library, its public functions become entrypoints.
Helpers called by those entrypoints remain reachable through ordinary Python
analysis. Other classes and private helpers receive no blanket exemption.
The local `robot.libraries.BuiltIn` provider is included implicitly when Robot
test data is present; other standard libraries require a `Library` setting.

Keyword discovery respects literal `ROBOT_AUTO_KEYWORDS` values, inherited
policies, `robot.api.deco.library`, `keyword`, and `not_keyword`, and a module's
literal `__all__`. For hybrid and dynamic libraries, Skylos retains the protocol
methods and recognizes literal keyword-name lists. An unknown computed list does
not expose every public helper. A `dir(self)` comprehension with a literal
`startswith` filter is limited to the selected class's methods. A library
decorated with `@library(listener="self")` also activates its known Robot
listener callbacks.

The same native decorator also works when applied as ordinary Python code,
such as `Library = library(auto_keywords=True)(Library)`. Skylos keeps the
original class and the decorator's keyword policy. A local replacement for
`library`, a replaced decorator factory, or a later changed class binding does
not provide that evidence.

YAML and JSON variable files do not activate similarly named Python providers.
For Python variable files, Skylos retains public module attributes, or public data
attributes on the selected class. A literal `__all__` limits those exports.
When `get_variables` or `getVariables` is present, that getter supplies variables
instead; unrelated module constants remain candidates for unused-variable
findings.

Skylos also follows direct method expressions in Robot test and task bodies,
such as `${OBJ.render()}` and `&{OBJECT FROM FILE.get_values()}`. The variable
must come from a named Python variable file, including one imported through a
resource, and its value must be a known source-owned constructor instance.
Only the exact method and its ordinary Python helpers become reachable.
Other methods, unrelated classes with the same method name, comments, and
escaped variable text receive no exemption.
Literal false `IF`/`WHILE` bodies and statically empty `FOR` bodies also supply
no method references. Known variable-file and table overrides affect these
guards; unknown conditions remain possible branches.

This object proof declines ambiguous variable providers, dynamic getters,
Robot variable reassignments, visible method replacement, custom construction
or attribute dispatch, and unknown receiver changes. Nested member chains,
general Python expressions, and calls inside user keyword bodies are outside
this bounded expression model. These limits do not change ordinary Python
reference or uncertainty handling.

Provider resolution supports explicit file paths, dotted module and class names,
the importing file's directory, and project roots `src`, `lib`, and `python`.
Ambiguous providers receive no exemption. Literal variables in Robot variable
sections and imported resources can supply paths, including `${CURDIR}` and
`${/}`. Unknown runtime values do not trigger a search for matching basenames
elsewhere in the repository.

Command-line variable-file imports, custom Python search paths, external
listener configuration, Libdoc command arguments, localized setting names, and
arbitrary computed keyword exports are outside this model. An unresolved
import does not suppress a finding. Existing suppressions remain available for
runtime configuration that static analysis cannot resolve.

The [Robot Framework User Guide](https://robotframework.org/robotframework/latest/RobotFrameworkUserGuide.html#creating-test-libraries)
describes the library protocols.
