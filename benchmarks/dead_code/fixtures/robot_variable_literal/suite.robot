*** Settings ***
Variables    values.py

*** Test Cases ***
Literal text
    Log    \${OBJ.render()}
    # ${OBJ.render()}

Inactive branch
    IF    ${False}
        Log    ${OBJ.render()}
    END
