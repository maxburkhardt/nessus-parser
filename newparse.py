#!/usr/bin/env python
## This script marshals the other parts of the parser

from reader import read
from statistics import stat_compute
from arguments import parse_arguments

if __name__ == '__main__':
    args = parse_arguments()
    csv_data = read(args.filename)
    environ = {}

    # process options which set flags for other modules
    if args.numeric_ids:
        environ['numeric_ids'] = True

    # process mutators, according to which ones were selected
    if args.condense_java:
        from mutators import condense_java
        condense_java.mutate(csv_data, environ)
    if args.select_adobe:
        from mutators import select_adobe
        select_adobe.mutate(csv_data, args.select_adobe, environ)
    if args.level:
        from mutators import level
        level.mutate(csv_data, args.level, environ)
    if args.hostname_regex:
        from mutators import hostname_regex
        hostname_regex.mutate(csv_data, args.hostname_regex, environ)

    # process output modules
    from output import text
    text.output(csv_data, environ)
