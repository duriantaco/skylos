*** Settings ***
Library    keywords.py

*** Test Cases ***
Read the value
    ${value}=    Measure
    Should Be Equal As Integers    ${value}    42
