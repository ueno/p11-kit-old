#!/usr/bin/python3

import re
import string
import typing

# Parsing

P11_FUNCTION_RE = re.compile(r'\A_CK_DECLARE_FUNCTION\s*\(C_(\w+), \((.*)\)\);')
P11_ARGUMENT_RE = re.compile(r'\s*([^,]+\s+\**)([^, ]+)')
P11_FUNCTION_LIST_MEMBER_RE = re.compile(r'\A\s*CK_C_(\S+)\s+.*;')

P11_X_FUNCTION_RE = re.compile(r'\Atypedef CK_RV \(\* CK_X_(\w+)\)\s*\((.*)\);')
P11_X_ARGUMENT_RE = re.compile(r'\s*([^,]+)')
P11_X_FUNCTION_LIST_MEMBER_RE = re.compile(r'\A\s*CK_X_(\S+)\s+.*;')

Argument = typing.NamedTuple('Argument',
                             [('name', str),
                              ('type', str)])
Function = typing.NamedTuple('Function',
                             [('name', str),
                              ('args', [Argument])])

class Parser(object):
    def __init__(self):
        self.__function_lines = list()
        self.__x_function_lines = list()
        self.__function_names = list()
        self.__x_function_names = list()
        self.__args = dict()
        self.__x_args = dict()
        self.functions = list()
        self.x_functions = list()

    def __read_pkcs11_h(self, infile):
        reading_list = False
        while True:
            l = infile.readline()
            if not l:
                break
            if l.startswith('_CK_DECLARE_FUNCTION'):
                line = l.strip()
                while not line.endswith(';'):
                    l = infile.readline()
                    if not l:
                        break
                    line += ' ' + l.strip()
                self.__function_lines.append(line)
                continue
            elif l.startswith('struct ck_function_list'):
                if not l.endswith(';'):
                    reading_list = True
                continue
            elif reading_list:
                match = P11_FUNCTION_LIST_MEMBER_RE.match(l)
                if match:
                    self.__function_names.append(match.group(1))
                continue
            else:
                continue
            break

    def __read_pkcs11i_h(self, infile):
        reading_list = False
        while True:
            l = infile.readline()
            if not l:
                break
            if l.startswith('typedef CK_RV (* CK_X_'):
                line = l.strip()
                while not line.endswith(';'):
                    l = infile.readline()
                    if not l:
                        break
                    line += ' ' + l.strip()
                self.__x_function_lines.append(line)
                continue
            elif l.startswith('struct _CK_X_FUNCTION_LIST'):
                if not l.endswith(';'):
                    reading_list = True
                continue
            elif reading_list:
                match = P11_X_FUNCTION_LIST_MEMBER_RE.match(l)
                if match:
                    self.__x_function_names.append(match.group(1))
                continue
            else:
                continue
            break

    def __parse_function_line(self, line):
        match = P11_FUNCTION_RE.match(line)
        (name, args) = (match.group(1), match.group(2))
        args = [Argument(arg.group(2), arg.group(1).strip())
                for arg in P11_ARGUMENT_RE.finditer(args)]
        return Function(name, args)

    def __parse_function_lines(self):
        for line in self.__function_lines:
            function = self.__parse_function_line(line)
            self.__args[function.name] = function.args
            self.functions.append(function)
        self.functions.sort(key=lambda x: self.__function_names.index(x.name))

    def __parse_x_function_line(self, line):
        match = P11_X_FUNCTION_RE.match(line)
        (name, args) = (match.group(1), match.group(2))
        args = [Argument('', arg.group(1).strip())
                         for arg in P11_X_ARGUMENT_RE.finditer(args)]
        return Function(name, args)

    def __parse_x_function_lines(self):
        for line in self.__x_function_lines:
            function = self.__parse_x_function_line(line)
            self.__x_args[function.name] = function.args
            self.x_functions.append(function)
        self.x_functions.sort(key=lambda x: self.__x_function_names.index(x.name))

    def parse(self, pkcs11_h, pkcs11i_h):
        self.__read_pkcs11_h(pkcs11_h)
        self.__read_pkcs11i_h(pkcs11i_h)
        self.__parse_function_lines()
        self.__parse_x_function_lines()
        for function in self.functions:
            args = self.__x_args.get(function.name)
            if args:
                for index, arg in enumerate(args[1:]):
                    old = function.args[index]
                    function.args[index] = Argument(old.name, arg.type)
        for function in self.x_functions:
            old = function.args[0]
            function.args[0] = Argument('self', old.type)
            args = self.__args.get(function.name)
            if args:
                for index, arg in enumerate(args):
                    old = function.args[index+1]
                    function.args[index+1] = Argument(arg.name, old.type)

# Code generation

P11_INDENT_RE = re.compile(r' {8}')

Config = typing.NamedTuple('Config',
                           [('parser', Parser),
                            ('exclude', [str])])

def format_type(type):
    if not type.endswith('*') and not type.endswith(' '):
        return type + ' '
    return type

class Template(object):
    def __init__(self, template):
        self.__template = string.Template(template)

    def __getitem__(self, name):
        if hasattr(self, name):
            return getattr(self, name)

    def substitute(self, **kwargs):
        self.substitute_kwargs = kwargs
        return self.__template.substitute(self, **kwargs)

class FunctionTemplate(Template):
    @property
    def function_name(self):
        function = self.substitute_kwargs['function']
        return function.name

    def get_arglist(self):
        function = self.substitute_kwargs['function']
        wrapper_function_name = self.substitute_kwargs['wrapper_function_name']
        indent = P11_INDENT_RE.sub('\t', (len(wrapper_function_name + ' (') * ' '))
        return ['{indent}{type}{name}'.format(indent=indent,
                                              type=format_type(arg.type),
                                              name=arg.name)
                for arg in function.args]

    @property
    def arglist(self):
        function = self.substitute_kwargs['function']
        wrapper_function_name = self.substitute_kwargs['wrapper_function_name']
        indent = P11_INDENT_RE.sub('\t', (len(wrapper_function_name + ' (') * ' '))
        return ',\n'.join(self.get_arglist()).strip()

    def get_args(self):
        function = self.substitute_kwargs['function']
        return [arg.name for arg in function.args]

    @property
    def args(self):
        function = self.substitute_kwargs['function']
        return ', '.join(self.get_args())

    @property
    def args2(self):
        return ', '.join(self.get_args()[1:])

class FileTemplate(Template):
    def __init__(self, template, function_template, config):
        self.function_template = function_template
        self.config = config
        super(FileTemplate, self).__init__(template)

    @property
    def function_list(self):
        result = list()
        for function in self.config.parser.x_functions:
            if function.name in self.config.exclude:
                continue
            result.append(self.function_template.substitute(function=function,
                                                            wrapper_function_name=self.wrapper_function_name(function)))
        return '\n'.join(result)

    @property
    def initializer_list(self):
        result = list()
        for function in self.config.parser.x_functions:
            if function.name not in self.config.exclude:
                result.append('\t' + self.wrapper_function_name(function))
            else:
                result.append('\tNULL')
        return ',\n'.join(result)

class BaseFunctionTemplate(FunctionTemplate):
    def __init__(self):
        super(BaseFunctionTemplate, self).__init__('''\
static CK_RV
${wrapper_function_name} (${arglist})
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_${function_name} (${args2});
}
''')

class BaseFileTemplate(FileTemplate):
    def __init__(self, config):
        super(BaseFileTemplate, self).__init__('''\
${function_list}

CK_X_FUNCTION_LIST p11_virtual_base = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },  /* version */
${initializer_list}
};
''',
        BaseFunctionTemplate(),
        config)

    def wrapper_function_name(self, function):
        return 'base_C_{function}'.format(function=function.name)

class StackFunctionTemplate(FunctionTemplate):
    def __init__(self):
        super(StackFunctionTemplate, self).__init__('''\
static CK_RV
${wrapper_function_name} (${arglist})
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_${function_name} (funcs, ${args2});
}
''')

class StackFileTemplate(FileTemplate):
    def __init__(self, config):
        super(StackFileTemplate, self).__init__('''\
${function_list}

CK_X_FUNCTION_LIST p11_virtual_stack = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },  /* version */
${initializer_list}
};
''',
        StackFunctionTemplate(),
        config)

    def wrapper_function_name(self, function):
        return 'stack_C_{function}'.format(function=function.name)

P11_TEMPLATE = {
    'base': BaseFileTemplate,
    'stack': StackFileTemplate
}

if __name__ == '__main__':
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='gen-wrapper')
    parser.add_argument('template', choices=['base', 'stack'],
                        help='name of the template')
    parser.add_argument('pkcs11', type=argparse.FileType('r'),
                        help='the pkcs11.h header file')
    parser.add_argument('pkcs11i', type=argparse.FileType('r'),
                        help='the pkcs11i.h header file')
    parser.add_argument('-x', '--exclude', action='append', type=str,
                        default=[],
                        help='exclude functions')
    args = parser.parse_args()

    parser = Parser()
    parser.parse(args.pkcs11, args.pkcs11i)
    template = P11_TEMPLATE[args.template]
    config = Config(parser, args.exclude)
    print(template(config).substitute())
