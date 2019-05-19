#!/usr/bin/env python3
# Prototyping tool for analyzing WireGuard implementations.
# Author: Peter Wu <peter@lekensteyn.nl>
# Licensed under the MIT license <http://opensource.org/licenses/MIT>.
import argparse
import inspect
import re
import sys
import traceback

from collections import OrderedDict

from state import State


def parse_name(line):
    # Match foo, foo.property, etc.
    m = re.match(
        r'^(\$?)([A-Za-z]\w+(\.[A-Za-z]\w+)*)(?:\s+|$|(?==))', line, re.ASCII)
    if not m:
        # Not a variable, no name either
        return 0, False, None
    return len(m.group(0)), bool(m.group(1)), m.group(2)


def parse_value(value, variables):
    if not value:
        return b''
    partlen, is_var, name = parse_name(value)
    if is_var:
        names = name.split('.')
        obj = variables[names.pop(0)]
        while names:
            obj = getattr(obj, names.pop(0))
        return obj
    try:
        return int(value, 0)
    except ValueError:
        pass
    if value[0] in '\'"':
        assert len(
            value) > 1 and value[-1] == value[0], 'Missing closing quote'
        value = value[1:-1]
    # Do not base64-decode this, otherwise Storage.resolve won't be able to
    # resolve results. to_bytes will convert other values as needed.
    return value


def print_commands(s, filter):
    for name, method in inspect.getmembers(s, inspect.ismethod):
        if name.startswith('_'):
            continue
        if filter and filter not in name:
            continue
        params = list(inspect.signature(method).parameters)
        print('%-20s %s' % (name, ' '.join(params)))


def print_vars(variables, params):
    for name, value in variables.items():
        print('%-20s %s' % (name, value))


def process_line(line, s, variables):
    # Variable names:
    #   a-z A-Z 0-9 _ (must begin with letter though)
    # Constants:
    #   number:     digits (123) or hexdigits (0xabc)
    #   string:     quoted strings or anything else.
    # Syntax examples (tokens are space separated):
    #   myvar = foo
    #   print myvar
    #   myvar = some_func val1 $var1 arg2=val2 some=$obj.property.value
    #   obj.property.value = 1234

    # Parse optional destination variable
    destvar = None
    partlen, _, name = parse_name(line)
    if partlen and line[partlen:].startswith('='):
        destvar = name
        line = line[partlen+1:].strip()

    if ' ' in line:
        cmd, params = line.split(None, 1)
    else:
        cmd, params = line, ''
    if cmd == 'print':
        print(parse_value(params, variables))
        return
    if cmd == 'help':
        print_commands(s, params)
        return
    if cmd == 'set':
        print_vars(variables, params)
        return
    action = getattr(s, cmd, None)
    if not action:
        if not destvar:
            print(f'Ignoring bad line: {line}')
            return
        else:
            # No action, try to parse it as a single constant.
            results = (parse_value(line, variables),)
    else:
        args, kwargs = [], {}
        for arg in params.split():
            partlen, is_var, name = parse_name(arg)
            if not is_var and arg[partlen:].startswith('='):
                assert '.' not in name, 'foo.bar=... is forbidden'
                kwargs[name] = parse_value(arg[partlen+1:].strip(), variables)
            else:
                args.append(parse_value(arg, variables))
        # Store results such that they can be accessed.
        results = action(*args, **kwargs)
        if results:
            if type(results) != tuple:
                results = (results,)
            for result in results:
                variables[result.name] = result
    if destvar and results:
        # And store it in a user-supplied destination variable if any.
        # XXX can only access the first variable for now.
        value = results[0]
        if '.' not in destvar:
            variables[destvar] = value
        else:
            names = destvar.split('.')
            obj, names = variables[destvar], names[1:]
            while len(names) > 1:
                obj = getattr(obj, names.pop(0))
            setattr(obj, names[0], value)
        return


def interactive_loop(keep_going):
    s = State()
    variables = OrderedDict()
    prompt = ''
    if sys.stdin.isatty():
        prompt = '# '
        keep_going = True
    while True:
        try:
            line = input(prompt).strip()
        except EOFError:
            break
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            process_line(line, s, variables)
        except Exception:
            traceback.print_exc()
            if not keep_going:
                break


parser = argparse.ArgumentParser()
parser.add_argument('--keep-going', '-k', action='store_true',
                    help='Continue processing commands after an error.')


def main():
    args = parser.parse_args()
    interactive_loop(args.keep_going)


if __name__ == '__main__':
    main()
