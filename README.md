# yarafs
A file scanner that will scan a specific path crossing all texts and binaries with Yara rulesets.

# Development setup
## Requirements
The requirements.txt is there for easy use to install. Use
```
pip install -r requirements.txt
```

Yara module >= 3.5.0

# How it works
YaraFS checks the current path that the yara script is being run in, and checks for the rules folder called "myrules". Once in there, it will read
from the master rule file called "master_rules.yar", which contains 'includes' of multiple yara rules. If you wish to add more rules, please modify
the master_rules.yar file.

![Example](http://imgur.com/oHiSD3r.png)

to use type
```
./yarafs
```

