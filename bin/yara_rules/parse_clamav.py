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
import sys
from string import maketrans, hexdigits

# Two groups of number separated by a comma, i.e. 200,400
range_offset_pattern = re.compile("(\d+),(\d+)")

# One capital letter followed by one or two letters/numbers (i.e S3, EOF, ...), then possibly a sign and a mix of
# comma / numbers. This matches offsets like S0+123, EOF-2, SE2, EP+5,10 etc.
extended_offset_pattern = re.compile("([A-Z][A-Z0-9]{1,2})(([+-])([0-9,]+))?")

# Matches {-number}
floating_jump_pattern = re.compile("\{\-([0-9]+)\}")


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
%s
    condition:
%s
}

"""


class MalformedRuleError(Exception):
    pass


# We need to keep a set of all the signatures seen, because there are duplicates in the ClamAV database and
# Yara doesn't like that.
RULES = set()


class YaraRule:
    def __init__(self, malware_name, signatures, logical_expression=None, is_daily=False):
        """
        Creates a Yara rule based on information obtained from a ClamAV signature.

        :param str malware_name: The name given by ClamAV to the malware
        :param list signatures: The set of hex bytes identifying the malware (ClamAV syntax) accompanied by their offset.
        :param str logical_expression: The conditions in which the signatures apply
        :param bool is_is_daily: Whether the rule comes from the daily signatures
        """
        self._meta_signature = malware_name
        self._conditions = []
        self._signatures = []
        self._logical_expression = logical_expression
        # Sanitize the rule name: no whitespace and must not start with a number
        self._rulename = malware_name.translate(maketrans(" \t", "__"))
        self._rulename = self._rulename.replace(".", "_dot_")     # Necessary, to avoid conflicts. Just replacing by
        self._rulename = self._rulename.replace("-", "_dash_")    # underscores just doesn't cut it when signatures
        self._rulename = self._rulename.replace(":", "_column_")  # exist for Dialer-317 and Dialer.317
        try:
            int(self._rulename)
            self._rulename = "_%s" % self._rulename
        except ValueError:
            pass
        # There may be name conflicts between daily and main rules :(
        if is_daily:
            self._rulename = "D_" + self._rulename

        # Translate the signature and offset to Yara syntax
        for i in range(0, len(signatures)):
            self._translate_signature(signatures[i][0], i)
            self._translate_offset(signatures[i][1], i)

    def _translate_signature(self, sig, index):
        if not sig:
            raise MalformedRuleError("Received an empty signature!")

        s = sig
        s = s.replace("*", " [-] ")  # Unbounded jump
        s = s.replace("{0}", "")  # Skipping no bytes. Useless but appears in one signature.
        s = re.sub("\{\d+\}$", "", s, count=1)  # Remove byte skips at the end of signatures.
        s = floating_jump_pattern.sub(" {0-\g<1>} ", s)  # Yara doesn't support [-X] jumps, we need [0-X]
        s = s.replace("{", "[").replace("}", "]")  # Byte skips
        # Try to guess if it isn't an hexadecimal pattern.
        if any(c in "ghijljmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ" for c in s):
            raise MalformedRuleError("Malformed rule: %s (%s)" % (self._meta_signature, s))
        else:
            self._signatures.append("$a%d = { %s }" % (index, s))

    def _translate_offset(self, offset, index):
        # Handle simple cases first: find pattern anywhere.
        if offset == "*":
            self._conditions.append("$a%d" % index)
            return

        # Handle simple cases first: direct offset.
        try:
            self._conditions.append("$a%d at %d" % (index, int(offset)))
            return
        except ValueError:
            pass

        # Handle simple cases first: range.
        match = re.match(range_offset_pattern, offset)
        if match is not None:
            try:
                o1 = int(match.group(1))
                o2 = int(match.group(1))
                self._conditions.append("$a%d in (%s .. %s)" % (index, o1, o1 + o2))
            except ValueError:
                self._conditions.append("$a%d in (%s .. %s + %s)" % (index, match.group(1), match.group(1), match.group(2)))
            return

        # In the version info:
        if offset == "VI":
            self._conditions.append("$a%d in (manape.version_info.start .. "
                                    "manape.version_info.start + manape.version_info.size)" % index)
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
                    self._conditions.append("$a%d in (manape.sections[%d].start .. "
                                            "manape.sections[%d].start + manape.sections[%d].size)"
                                            % (index, num_section, num_section, num_section))
                    return  # No need to look at offsets for SEx

            # Now we have the base relative to which the offset is.
            if base_yara_offset is None:
                print "Unhandled extended condition: %s" % offset
                return

            # Simple case: just an offset
            if not range_offset_pattern.match(match.group(4)):
                if int(match.group(4)) != 0:
                    self._conditions.append("$a%d at %s %s %s" % (index, base_yara_offset, match.group(3), match.group(4)))
                else:
                    self._conditions.append("$a%d at %s" % (index, base_yara_offset))
            else:
                split = match.group(4).split(",")
                x = int(split[0])
                y = int(split[1])
                if match.group(2) == '+':
                    self._conditions.append("$a%d in (%s+%d .. %s + %d)" \
                                      % (index, base_yara_offset, x, base_yara_offset, x + y))
                else:
                    if y < x:
                        self._conditions.append("$a%d in (%s - %d .. %s - %d)" \
                                          % (index, base_yara_offset, x, base_yara_offset, x - y))
                    elif y > x:
                        self._conditions.append("$a%d in (%s - %d .. %s + %d)" \
                                          % (index, base_yara_offset, x, base_yara_offset, y - x))
                    else:  # x == y
                        self._conditions.append("$a%d in (%s - %d .. %s)" % (index, base_yara_offset, x, base_yara_offset))
        else:
            raise MalformedRuleError("Unable to understand the following offset: %s" % offset)

    def get_meta_signature(self):
        return self._meta_signature

    def __eq__(self, other):
        return self._meta_signature == other.get_meta_signature()

    def __str__(self):
        if len(self._signatures) == 0 or len(self._conditions) == 0:
            raise ValueError("Not enough information to create a Yara rule!")

        signatures = ""
        for sig in self._signatures:
            signatures += "\t\t%s" % sig
            if sig is not self._signatures[-1]:
                signatures += "\n"

        conditions = "\t\t"
        if self._logical_expression is None:
            if len(self._signatures) == 1:
                conditions += self._conditions[0]
            else:
                conditions += "any of them"
        else:
            tokens = re.findall("([=,<>\(\)&\|]|\d+)", self._logical_expression)
            i = 0
            while i < len(tokens):
                t = tokens[i]
                if t == "(" or t == ")":
                    conditions += t
                elif t == "&":
                    conditions += " and "
                elif t == "|":
                    conditions += " or "
                elif t == ">" or t == "<" or t == "," or t == "=":
                    # If they haven't been detected while looking ahead, it means that
                    # they arrive after a full expression (i.e. (0&1)>X,Y), which can't
                    # be translated to a Yara rule as far as I know.
                    print "Unable to translate a logical signature for %s. Skipping..." % self._meta_signature
                    return ""
                else:
                    try:
                        index = int(t)
                        # Check for a negation or a count
                        if i + 2 < len(tokens) and (tokens[i+1] == "=" or tokens[i+1] == ">" or tokens[i+1] == "<"):
                            if i + 3 < len(tokens) and tokens[i+2] == ",":
                                print "Unable to translate a logical signature for %s. Skipping..." % self._meta_signature
                                return ""
                            if tokens[i+1] == "=" and tokens[i+2] == "0":  # Negation
                                conditions += "not %s" % self._conditions[index]
                                i += 2  # Skip the "=0"
                            else:  # Count
                                if tokens[i+1] == "=":
                                    tokens[i+1] = "=="  # Yara uses the comparison symbol.
                                # I realize that some nuance is lost here. Unfortunately, Yara does not support
                                # expressions like "#a0 in a .. b > N". I'm generating "$a0 and #a0 > N" instead,
                                # I assume that not many rules will be meaningfully affected by this choice.
                                try:
                                    conditions += "(%s and #a%d %s %d)" % ((self._conditions[index],
                                                                            index,
                                                                            tokens[i+1],
                                                                            int(tokens[i+2])))
                                    i += 2
                                except ValueError:
                                    raise MalformedRuleError("Unexpected count.")

                        else:
                            conditions += self._conditions[index]  # The token is the number of the rule
                    except ValueError:
                        print "%s token not implemented!" % t
                        sys.exit(1)
                i += 1

        return yara_rule_template % (self._rulename, self._meta_signature, signatures, conditions)


def parse_ndb(input, output, is_daily=False):
    with open(input) as f:
        with open(output, 'ab') as g:
            for line in f:
                data = line.rstrip("\n").split(":")
                malware_name = data[0]
                target_type = int(data[1])
                offset = data[2]
                signature = data[3]
                # Ignore minfl & maxfl, since they represent ClamAV internal engine functionality levels.

                # We only care about signatures for PE executables.
                if target_type != TargetType.PE and target_type != TargetType.ANY:
                    continue

                # Ignore exploits, are we are only interested in malware signatures
                if ".Exploit." in malware_name:
                    continue

                try:
                    rule = YaraRule(malware_name, [[signature, offset]], is_daily=is_daily)
                except MalformedRuleError:
                    print "Rule %s seems to be malformed. Skipping..." % malware_name
                    continue

                if not rule.get_meta_signature() in RULES:
                    RULES.add(rule.get_meta_signature())
                    g.write(rule.__str__())
                else:
                    print "Rule %s already exists!" % rule.get_meta_signature()


def parse_ldb(input, output, is_daily=False):
    with open(input) as f:
        with open(output, 'ab') as g:
            for line in f:
                data = line.rstrip("\n").split(";")
                malware_name = data[0]
                target_block = dict()
                for block in data[1].split(","):
                    target_block[block.split(":")[0]] = block.split(":")[1]
                logical_expression = data[2]
                rules = data[3:]

                if int(target_block["Target"]) != TargetType.PE and int(target_block["Target"]) != TargetType.ANY:
                    continue

                # Unsupported fuzzy hashes of the icons
                if "IconGroup1" in target_block or "IconGroup2" in target_block:
                    continue
                # Also disregard rules for files contained in other files
                if "Container" in target_block:
                    continue

                if any('!' in r for r in rules):  # Skip rules containing "!" such as "...!(01|02|03)..."
                    continue                      # which do not translate to Yara rules.

                signatures = []
                for r in rules:
                    r_split = r.split(":")
                    if len(r_split) > 1:
                        signatures.append([r_split[1], r.split(":")[0]])
                    else:
                        signatures.append([r, "*"])

                try:
                    rule = YaraRule(malware_name, signatures, logical_expression=logical_expression, is_daily=is_daily)
                    translated_rule = rule.__str__()
                except MalformedRuleError:
                    print "Rule %s seems to be malformed. Skipping..." % malware_name
                    continue

                if not rule.get_meta_signature() in RULES and translated_rule:
                    RULES.add(rule.get_meta_signature())
                    g.write(translated_rule)
                elif translated_rule:
                    print "Rule %s already exists!" % rule.get_meta_signature()


def main():
    parser = argparse.ArgumentParser(description="Parses ClamAV signatures and translates them to Yara rules.")
    parser.add_argument("-i", "--input", dest="input", help="The file to parse.")
    parser.add_argument("-o", "--output", dest="output", help="The destination file for the Yara rules.")
    args = parser.parse_args()
    if args.input.endswith(".ndb"):
        parse_ndb(args.input, args.output)
    elif args.input.endswith(".ldb"):
        parse_ldb(args.input, args.output)


if __name__ == "__main__":
    main()
