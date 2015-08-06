#!/usr/bin/env python

"""
    This file is part of Manalyze.

    Manalyze is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Manalyze is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Manalyze.  If not, see <http://www.gnu.org/licenses/>.
"""
import argparse
import re
from string import maketrans

# Two groups of number separated by a comma, i.e. 200,400
range_offset_pattern = re.compile("([0-9]+),([0-9]+)")

# One capital letter followed by up to to letters/numbers (i.e S3, EOF, ...), then possibly a sign and a mix of comma / numbers
# This matches offsets like S0+123, EOF-2, SE2, EP+5,10 etc.
extended_offset_pattern = re.compile("([A-Z][A-Z0-9]{1,2})(([+-])([0-9,]+))?")

# Matches {-number}
floating_jump_pattern = re.compile("\{\-([0-9]+)\}")

# ClamAV jump patterns

class TargetType:
    ANY = 0
    PE = 1
    OLE = 2
    HTML = 3
    MAIL = 4
    GRAPHICS = 5
    ELF = 6
    ASCII = 7
    MACHO = 9
    PDF = 10
    FLASH = 11
    JAVA = 12

yara_rule_template = """rule %s
{
    meta:
        signature = \"%s\"
    strings:
        $a0 = { %s }
    condition:
        $a0%s
}

"""


class YaraRule:

    def __init__(self, malware_name, offset, signature):
        """
        Creates a Yara rule based on information obtained from a ClamAV signature.

        :param str malware_name: The name given by ClamAV to the malware
        :param str offset: Where the signature should be searched (ClamAV syntax)
        :param str signature: The hex byted identifying the malware (ClamAV syntax)
        """
        self._meta_signature = malware_name
        self._condition = None
        self._signature = None

        # Sanitize the rule name: no whitespace and must not start with a number
        self._rulename = malware_name.translate(maketrans(" \t", "__"))
        self._rulename = self._rulename.replace(".", "_dot_")   # Necessary, to avoid conflicts. Just replacing by
        self._rulename = self._rulename.replace("-", "_dash_")  # underscores just doesn't cut it when signatures
        try:                                                    # exist for Dialer-317 and Dialer.317
            int(self._rulename)
            self._rulename = "_%s" % self._rulename
        except ValueError:
            pass

        # Translate the signature and offset to Yara syntax
        self._translate_signature(signature)
        self._translate_offset(offset)
        pass

    def get_signature(self):
        return self._signature

    def get_condition(self):
        return self._condition

    def get_meta_signature(self):
        return self._meta_signature

    def __eq__(self, other):
        return self._meta_signature == other.get_meta_signature()

    def __str__(self):
        if self._signature is None or self._condition is None:
            raise ValueError("Not enough information to create a Yara rule! signature = %s ; condition = %s"
                             % (self._signature, self._condition))
        return yara_rule_template % (self._rulename, self._meta_signature, self._signature, self._condition)

    def _translate_signature(self, sig):
        self._signature = sig.replace("*", " [-] ")  # Unbounded jump
        self._signature = floating_jump_pattern.sub(" {0-\g<1>} ", self._signature)  # Yara doesn't support [-X] jumps, we need [0-X]
        self._signature = self._signature.replace("{", "[").replace("}", "]")  # Byte skips

    def _translate_offset(self, offset):
        # Handle simple cases first: find pattern anywhere.
        if offset == "*":
            self._condition = ""
            return

        # Handle simple cases first: direct offset.
        try:
            self._condition = " at %d" % int(offset)
            return
        except ValueError:
            pass

        # Handle simple cases first: range.
        match = re.match(range_offset_pattern, offset)
        if match is not None:
            self._condition = " in (%s .. %s)" % (match.group(1), match.group(2))
            return

        # Now, the complex cases: extended conditions.
        match = re.match(extended_offset_pattern, offset)
        if match is not None:  # Relative offset (to EOF, EP, etc.)
            relative_to = match.group(1)

            base_yara_offset = None
            if relative_to == "EP":
                base_yara_offset = "manape.ep"

            # Conditions regarding the end of file
            if relative_to == "EOF":
                base_yara_offset = "filesize"

            if relative_to[0] == "S":
                try:
                    section_number = int(relative_to[1:])
                    base_yara_offset = "manape.sections[%d].start" % section_number
                except ValueError:
                    pass

                if relative_to == "SL":  # Start of the last section
                    base_yara_offset = "manape.sections[manape.num_sections].start"
                elif relative_to[1] == 'E':  # SEx : contained inside section x
                    num_section = int(relative_to[2:])
                    self._condition = " in (manape.sections[%d].start .. manape.sections[%d].start + manape.sections[%d].size)" \
                                       % (num_section, num_section, num_section)
                    return  # No need to look at offsets for SEx

            # Now we have the base relative to which the offset is.
            if base_yara_offset is None:
                print "Unhandled extended condition: %s" % offset
                return

            # Simple case: just an offset
            if not range_offset_pattern.match(match.group(4)):
                if int(match.group(4)) != 0:
                    self._condition = " at %s %s %s" % (base_yara_offset, match.group(3), match.group(4))
                else:
                    self._condition = " at %s" % base_yara_offset
            else:
                splitted = match.group(4).split(",")
                x = int(splitted[0])
                y = int(splitted[1])
                if match.group(2) == '+':
                    self._condition = " in (%s+%d .. %s + %d)" \
                                      % (base_yara_offset, x, base_yara_offset, x + y)
                else:
                    if y < x:
                        self._condition = " in (%s - %d .. %s - %d)" \
                                          % (base_yara_offset, x, base_yara_offset, x - y)
                    elif y > x:
                        self._condition = " in (%s - %d .. %s + %d)" \
                                          % (base_yara_offset, x, base_yara_offset, y - x)
                    else:  # x == y
                        self._condition = " in (%s - %d .. %s)" % (base_yara_offset, x, base_yara_offset)
        else:
            print "Unable to understand the following offset: %s" % offset


def main():
    parser = argparse.ArgumentParser(description="Parses ClamAV signatures and translates them to Yara rules.")
    parser.add_argument("-i", "--input", dest="input", help="The file to parse.")
    parser.add_argument("-o", "--output", dest="output", help="The destination file for the Yara rules.")
    args = parser.parse_args()

    # We need to keep a set of all the signatures seen, because there are duplicates in the ClamAV database and
    # Yara doesn't like that.
    rules = set()

    with open(args.input) as f:
        with open(args.output, 'ab') as g:
            for line in f:
                data = line.rstrip("\n").split(":")
                malware_name = data[0]
                target_type = int(data[1])
                offset = data[2]
                signature = data[3]
                # Ignore minfl & maxfl, since they represent ClamAV internal engine functionality levels.

                # We only care about signatures for PE executables.
                if target_type != TargetType.PE:
                    continue

                rule = YaraRule(malware_name, offset, signature)

                if not rule.get_meta_signature() in rules:
                    rules.add(rule.get_meta_signature())
                    g.write(rule.__str__())
                else:
                    print "Rule %s already exists!" % rule.get_meta_signature()


if __name__ == "__main__":
    main()
