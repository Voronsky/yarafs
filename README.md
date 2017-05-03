# yarafs
A file scanner that will scan a specific path crossing all texts and binaries with Yara rulesets.

# How it works
It will read the configuration file, and check where the rule sets are defined, by default it will go to another folder in the same directory
and read the rules there, in order to then scan the user's home directory.
