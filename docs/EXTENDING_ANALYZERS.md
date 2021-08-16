## Add New Vulnerabilities or Untrusted Input Sources
New and custom vulnerabilities or untrusted input sources can be added by editing [analyzers.yml](analyzers.yml).
Analyzers.yml is organized into two sections: analyzers and sources. 

1) Analyzers: Analyzers describe a specific vulnerability type (like command injection). 
    They configure which functions to look for to identify the vulnerability, the message to be displayed when 
    the vulnerability is found, a description of the vulnerability, and the vulnerability name displayed when the vulnerability is found. When an analyzer is added, GoKart will look for any functions specified as vulnerable. If a function listed is found, GoKart will trace the input back to the source. If the source is determined to be untrusted (as defined in the sources section of the yml), GoKart will output the vulnerability. The template to add a new vulnerability scanner looks like this:

    ```
    analyzers:
        "vulnerability1 name to be printed out":
            doc: "vulnerability1 description"
            message: "vulnerability1 message to be printed out"
            vuln_calls:
                "vulnerable functions package1":
                    - "vulnerable function1 name"
                    - "vulnerable function2 name"
                "vulnerable functions package2":
                    ...
        "vulnerability2 name to be printed out":
            doc: "vulnerability2 description"
            ...
    ```

    Here is an example of a vulnerability that would go in the "analyzers" section: 

    ```
    "Command Injection":
        doc: "OS Command Injection"
        message: "Danger: possible command injection detected"
        vuln_calls:
            "os/exec":
            - "Command"
            - "CommandContext"
    ```

    To add a new vulnerability scanner (an analyzer), add a correctly formatted vulnerability with all fields filled out to the "analyzers" section. Make sure all indents are correct (use current vulnerabilities in the yml for reference on proper indentation). Note that not all vulnerabilities are able to be configured in the yml. Take RSA Keylength Checking for example- to test if an RSA key is too short, mathematical calculations often have to be performed. Vulnerabilities like these that require more than identifying functions and tracing back the input will have to be manually configured by adding an analyzer in the "analyzers" folder (not in the yml). The yml is for adding vulnerabilities that (1) only require identifying vulnerable functions and (2) are only dangerous if they take untrusted input.

2) Sources: Sources describe a source that should be considered untrusted. An untrusted source is a source that may contain user input and thus cannot be trusted to be used in a potentially vulnerable function. For example, the potentially vulnerable function `DB.Query(params)` is considered vulnerable and will be output as a vulnerability by GoKart if `params` can be traced back to an untrusted input source. GoKart identifies whether or not a source is untrusted by looking through the sources listed in the yml. Sources can be variables, functions, or types. To add a source that should be considered untrusted, go to the correct category and add these lines:

    ```
    "package name":
        - "variable/function/type name"
    ```

    If the package already exists in the sources section, add the variable/function/type underneath that package as each package can contain multiple vulnerable sources.