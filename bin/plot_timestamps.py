#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Plot compilation timestamps of a collection of binaries to a graph.
# This script is part of Manalyze, which is released under the terms of the GPLv3 license.
#
# Install:  $> pip install ascii_graph numpy
# Usage:    $> manalyze -p resources -o json [files] | ./plot_timestamps.py
#
# This script reuses code from x0rz's tweets_analyzer script: https://github.com/x0rz/tweets_analyzer

import argparse
import datetime
import json
import numpy
import os
import re
import sys

from ascii_graph import Pyasciigraph
from ascii_graph.colors import Gre, Yel, Red
from ascii_graph.colordata import hcolor

###############################################################################
# Object model
###############################################################################

class Results:
    """
    An object into which the data collected from each sample is aggregated.
    """
    def __init__(self):
        self.activity_hourly = {
            ("%02i:00" % i): 0 for i in range(24)
        }
        self.activity_weekly = {
            "%i" % i: 0 for i in range(7)
        }
        self.activity_yearly = {}
        self.detected_languages = set()
        self.ignored_samples = 0
        self.possible_timezones = set()

###############################################################################
# Program intelligence
###############################################################################

def process_sample(s, result, args):
    """
    This function extracts data from a Manalyze report for a given PE and adds
    the relevant data to the result object.
    :param s: The input report to process.
    :param result: The result object that collects data.
    :param args: The parsed arguments of the program.
    :return: None
    """
    try:  # Take the resource timestamp if available, as it's usually more reliable.
        timestamp = s["Plugins"]["resources"]["plugin_output"]["The resource timestamps differ from the PE header"][0]
    except KeyError:
        timestamp = s["Summary"]["Compilation Date"]
    timestamp = datetime.datetime.strptime(timestamp, "%Y-%b-%d %H:%M:%S")

    # Check if the plugin reported a possible timestamp mismatch hinting at the compilation machine's timezone.
    try:
        matcher = re.compile(r"The binary may have been compiled on a machine in the (UTC[+-][0-9]{1,2}) timezone")
        for output in s["Plugins"]["resources"]["plugin_output"]:
            m = matcher.match(output)
            if m:
                result.possible_timezones.add(m.group(1))
                break
    except KeyError:
        pass

    # Exclude samples that are too old. Yes, yes, leap years are not taken into account.
    date_limit = datetime.datetime.now() - datetime.timedelta(days=args.ignore_older_than * 365)
    if timestamp < date_limit:
        result.ignored_samples += 1
        return

    # Adjust the timezone if requested by the user.
    if args.rebase_timezone:
        timestamp += args.rebase_timezone

    # Update counts
    result.activity_hourly["%02i:00" % timestamp.hour] += 1
    result.activity_weekly[str(timestamp.weekday())] += 1
    result.activity_yearly[timestamp.year] = result.activity_yearly.get(timestamp.year, 0) + 1

    # Update language data
    if "Detected languages" in s["Summary"]:
        result.detected_languages.update(lang for lang in s["Summary"]["Detected languages"])

###############################################################################
# Miscellaneous functions
###############################################################################

def int_to_weekday(day):
    weekdays = "Monday Tuesday Wednesday Thursday Friday Saturday Sunday".split()
    return weekdays[int(day) % len(weekdays)]

###############################################################################
# Pretty printing functions
###############################################################################

GREEN = '\033[92m'
ORANGE = '\033[93m'
RED = '\033[91m'
END = '\033[0m'

# -----------------------------------------------------------------------------

def supports_color():
    # Copied from https://github.com/django/django/blob/master/django/core/management/color.py
    plat = sys.platform
    supported_platform = plat != 'Pocket PC' and (plat != 'win32' or 'ANSICON' in os.environ)
    is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    if not supported_platform or not is_a_tty:
        return False
    return True

# -----------------------------------------------------------------------------

if supports_color():
    def red(text): return RED + text + END
    def orange(text): return ORANGE + text + END
    def green(text): return GREEN + text + END
else:
    def red(text): return text
    def orange(text): return text
    def green(text): return text

# -----------------------------------------------------------------------------

def error(text): return "[" + red("!") + "] " + red("Error: " + text)
def warning(text): return "[" + orange("*") + "] Warning: " + text
def success(text): return "[" + green("*") + "] " + green(text)
def info(text): return "[ ] " + text

# -----------------------------------------------------------------------------

def print_charts(dataset, title, args, weekday=False):
    chart = []
    keys = sorted(dataset.keys())
    mean = numpy.mean(list(dataset.values()))
    median = numpy.median(list(dataset.values()))

    for key in keys:
        if dataset[key] >= median * 1.33:
            displayed_key = "%s (\033[92m+\033[0m)" % (int_to_weekday(key) if weekday else key)
        elif dataset[key] <= median * 0.66:
            displayed_key = "%s (\033[91m-\033[0m)" % (int_to_weekday(key) if weekday else key)
        else:
            displayed_key = (int_to_weekday(key) if weekday else key)
        chart.append((displayed_key, dataset[key]))

    thresholds = {
        int(mean): Gre, int(mean * 2): Yel, int(mean * 3): Red,
    }

    data = hcolor(chart, thresholds)

    graph = Pyasciigraph(
        separator_length=4,
        multivalue=False,
        human_readable='si',
    )

    for line in graph.graph(title, data):
        if args.no_color:
            ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
            line = ansi_escape.sub('', line)
        print(line)
    print("")

###############################################################################
# Main
###############################################################################

def validate_args():
    """
    Parses the script arguments and makes sure that they make sense.
    :return: The parsed and validated arguments of the script.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-color', action='store_true', help='Disables color in the graphs')
    # The rationale for this is that we want to exclude samples which have an obvious fake compilation date, as well
    # as those that have a default timestamp set in the nineties.
    parser.add_argument('--ignore-older-than', '-i', default=10, type=int,
                        help="Ignore samples that are more than N years old. (Default: 10)")
    parser.add_argument('--rebase-timezone', '-t',
                        help="Translates all the timestamps to the desired timezone. (Ex: 'UTC+2', 'UTC-6'...)")
    parser.add_argument('--charts', '-c', action="append",
                        help="The types of charts to plot. Can be any combination of day, week, year or all (default).")
    parser.add_argument('json_file', nargs="?",
                        help="A file containing manalyze's output. Otherwise, data is read from stdin.")
    args = parser.parse_args()

    # If the OS doesn't support colored output, disable it automatically.
    if not args.no_color:
        args.no_color = not supports_color()

    # Make sure the requested chart types are valid.
    if not args.charts or "all" in args.charts:
        args.charts = ["day", "week", "year"]
    else:
        for chart_type in args.charts:
            if chart_type not in ["day", "week", "year"]:
                print(error("%s is not a valid chart type." % chart_type))
                sys.exit(-1)

    if args.rebase_timezone:  # Convert the requested timezone into a timedelta.
        try:
            matcher = re.compile(r"(UTC)?([+-][0-9]{1,2})")
            args.rebase_timezone = datetime.timedelta(hours=int(matcher.match(args.rebase_timezone).group(2)))
        except:
            print(error("%s is not a valid timezone." % args.rebase_timezone))
            sys.exit(-1)
    return args

# -----------------------------------------------------------------------------

def get_user_input(args):
    """
    Obtains the parsed PE data, either from a pre-existing file or stdin.
    :param args: The parsed arguments of the program.
    :return: A dictionary representing the parsed files.
    """
    if args.json_file:
        with open(args.json_file, 'r') as f:
            report = f.read()
    else:
        report = sys.stdin.read()

    try:
        report = json.loads(report)
    except json.decoder.JSONDecodeError:
        print(error("The input is not a valid JSON document."))
        sys.exit(-1)
    return report

# -----------------------------------------------------------------------------

def main():
    args = validate_args()
    report = get_user_input(args)
    r = Results()

    for sample in report.values():
        process_sample(sample, r, args)  # Extract data from each parsed PE.

    # Print global stats
    print(success("Processed %d samples." % len(report)))
    if r.ignored_samples:
        print(warning("Ignored %d samples because they were more than %d years old." % (r.ignored_samples, args.ignore_older_than)))
    if r.detected_languages:
        print(info("Languages detected in all the samples:"))
        for lang in r.detected_languages:
            print("\t\t%s" % lang)
    if r.possible_timezones:
        print(info("Some of the binaries were likely compiled in the following timezones:"))
        for tz in r.possible_timezones:
            print("\t\t%s" % tz)

    # Print the charts.
    print("\n###############################################################################")
    # The any() condition verifies that the input contains data to plot.
    if "day" in args.charts and any(x for x in r.activity_hourly.values()):
        print_charts(r.activity_hourly, "Distribution of timestamps over the day", args)
    if "week" in args.charts and any(x for x in r.activity_weekly.values()):
        print_charts(r.activity_weekly, "Distribution of timestamps over the week", args, weekday=True)
    if "year" in args.charts and any(x for x in r.activity_yearly.values()):
        print_charts(r.activity_yearly, "Distribution of timestamps over the years", args)


if __name__ == "__main__":
    main()
