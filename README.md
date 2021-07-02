# stoq_transformer
Transform step in malwarETL pipeline for captured files

This includes a custom stoQ plugin for Lief because I want to make sure the data collected here matches the 
EMBER dataset format. The `to_json` LIEF method does not include some values if they're False, empty lists, etc in 
the final json, and that is a problem for training since those are values that I want to be able to learn on. Also,
some of the values were strangely different (`len(lief_obj.imported_functions) != len(lief_json["imports}]`) so I could
not be convinced that the json dump was clearly comparable to the EMBER dataset data.

