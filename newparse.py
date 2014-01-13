#!/usr/bin/env python
## This script marshals the other parts of the parser

from reader import read
from arguments import parse_arguments
import statistics

if __name__ == '__main__':
    args = parse_arguments()
    csv_data = read(args.filename)
    environ = {}

    # process options which set flags for other modules
    if args.numeric_ids:
        environ['numeric_ids'] = True
    else:
        environ['numeric_ids'] = False

    # process mutators, according to which ones were selected
    if args.condense_java:
        from mutators import condense_java
        condense_java.mutate(csv_data, environ)
    if args.select_adobe:
        from mutators import select_adobe
        select_adobe.mutate(csv_data, args.select_adobe, environ)
    # level and plugin_list don't really make sense together,
    # so we ignore level if plugin_list is present
    if args.level and args.plugin_list == None:
        from mutators import level
        level.mutate(csv_data, args.level, environ)
    if args.hostname_regex:
        from mutators import hostname_regex
        hostname_regex.mutate(csv_data, args.hostname_regex, environ)
    if args.plugin_list:
        from mutators import plugin_list
        plugin_list.mutate(csv_data, args.plugin_list, environ)

    # print some statistics
    statistics.output(csv_data)

    # process output modules
    from output import text
    text.output(csv_data, environ)
