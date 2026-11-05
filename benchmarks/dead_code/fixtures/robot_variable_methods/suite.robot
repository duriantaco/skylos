*** Settings ***
Variables    values.py

*** Test Cases ***
Read the value
    Should Be Equal    ${OBJ.render()}    ready
