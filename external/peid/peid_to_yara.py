#!/usr/bin/env python
# encoding: utf-8
#
# Tested on Linux (Ubuntu), Windows XP/7, and Mac OS X
#
'''
untitled.py

Created by Matthew Richard on 2010-03-12.
Ported to py3 by Julien (jvoisin) Voisin on feb2014
Updated by JusticeRage on 2014-03-19 (added metadata, NSA-style)
Copyright (c) 2010. All rights reserved.

'''

import os
import re
import argparse
import collections


def main():
    parser = argparse.ArgumentParser(description='PEiD to yara rules converter')
    parser.add_argument('-n', '--no-ep', dest='no_ep', action='store_true',
        default=False, help='no entrypoint restriction')
    parser.add_argument('files', metavar='files', type=str, nargs='+',
        help='scanned filenames')
    parser.add_argument('-o', '--output-file', action='store', dest='outfile',
        help='output filename')

    opts = parser.parse_args()

    if opts.outfile is None:
        parser.error('You must specify an output filename!\n')
    elif opts.files is None:
        parser.error('You must supply at least one filename!\n')
    else:
        for fin in opts.files:
            if not os.path.isfile(fin):
                parser.error('%s does not exist' % fin)

    # yara rule template from which rules will be created
    yara_rule = '''
rule %s
{
meta:
    packer_name = \"%s\"
strings:
    %s
condition:
    %s
}

    '''
    rules = collections.defaultdict(lambda: set(), {})

    #  read the PEiD signature files
    data = ' '.join([open(f, 'r').read() for f in opts.files])

    #  every signature takes the form of
    #  [signature_name]
    #  signature = hex signature
    #  ep_only = (true|false)
    signature = re.compile(r'''
        \[\d*(.+?)\]\r?\n                   # rule name (Can not start with a number)
        signature\ =\ (?:\?\?\ )*(.+?)\r?\n # signature (Can not start with '?? '*)
        ep_only\ =\ (true|false)            # ep_only
        ''', re.MULTILINE | re.DOTALL | re.VERBOSE)

    # rule name has the same constraints as a C variable name 
    rules_cpt = 0
    name_filter = re.compile(r'(\W)')
    for match in signature.finditer(data):
        name = name_filter.sub('_', match.group(1))
        rules[name].add((match.group(2), match.group(3), match.group(1)))
        rules_cpt += 1
    print('[+] Found %d signatures in PEiD input file' % rules_cpt)

    output = ''
    for rule in list(rules.keys()):
        detects = ''
        conds = '\t'
        counter = 0
        for (detect, use_ep, packer_name) in rules[rule]:
            # create each new rule using a unique numeric value
            # to allow for multiple criteria and no collisions
            detects += '\t$a%d = { %s }\n' % (counter, detect)

            if counter > 0:
                conds += ' or '

            # if the rule specifies it should be at EP we add
            # the yara specifier 'at entrypoint'
            conds += '$a%d' % counter
            if use_ep == 'true' and opts.no_ep is False:
                conds += ' at entrypoint'
            counter += 1

        # add the rule to the output
        output += yara_rule % (rule, packer_name.replace("\"", "'"), detects, conds)

    # could be written to an output file
    with open(opts.outfile, 'w') as fout:
        fout.write(output)

    print('[+] Wrote %d rules to %s' % (len(rules), opts.outfile))

if __name__ == '__main__':
    main()
