## module to parse arguments passed in on command line
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description='Process Nessus CSVs')
    parser.add_argument('filename', metavar='filename', type=str,
            help="Nessus CSV file to parse.")
    parser.add_argument('--condense-java', dest='condense_java',
            action='store_true', help='combine all java-related vulns in to one category.')
    parser.add_argument('--select-adobe', dest='select_adobe', type=str,
            choices=['only', 'none'],
            help='output either ONLY Adobe vulnerabilities or NO Adobe vulnerabilities')
    parser.add_argument('--level', dest='level', type=str, 
            choices=['Critical', 'High', 'Medium', 'Low', 'None'],
            help='Show vulns of risk level <level>.')
    parser.add_argument('--filter-hostname', dest='hostname_regex', type=str,
            help='only show hostnames that match the regular expression <regex>. Suggested values: AEIO, SAS, etc. Keep things to one word, or be prepared to debug your regexes.')
    parser.add_argument('--filter-plugin', dest='plugin_list', type=str,
            help='only show the listed plugins. Separate desired plugins by commas, WITHOUT spaces. NOTE: this overrides the --level directive.')
    parser.add_argument('--filter-group', dest='group_file', type=str,
            help='read in regular expressions from the given file (one per line), and only process hosts that match one of them.')
    parser.add_argument('--create-tickets', dest='recipe_file', type=str,
            help='makes RT tickets for all hosts produced in the report.')
    parser.add_argument('--create-excel', dest='excel_file', type=str,
            help='creates an Excel file with the information produced by this script.')
    parser.add_argument('--numeric-ids', dest='numeric_ids', action='store_true',
            help='represent plugins by their ID, not their human-readable name')
    parser.set_defaults(condense_java=False, level='Critical', numeric_ids=False)

    return parser.parse_args()
