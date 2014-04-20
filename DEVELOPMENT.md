DEVELOPMENT
===========

The AbstractCommand needs to load a options object.

Then needs to load a config file, either from current working directory or the home directory.

Returns an Options object.

During execution, the getStorage command will override the settings over the Options object if it existed.