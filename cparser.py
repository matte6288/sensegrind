import argparse

from pycparser import c_parser, c_ast, parse_file

import os

parser = argparse.ArgumentParser()

parser.add_argument("-f", "--file_name", help="The name of the C file", required=True)
parser.add_argument("-o", "--output_file_name", help="The name of the output C file", required=False, default="varout.txt")

args = parser.parse_args()

class VariableVisitor(c_ast.NodeVisitor):

    def __init__(self):

        self.variables = set()

    def visit_Decl(self, node):

        if isinstance(node.type, c_ast.ArrayDecl):

            self.variables.add(node.name)

        if isinstance(node.type, c_ast.TypeDecl):

            self.variables.add(node.name)

backup_file = args.file_name + "bck"

with open (args.file_name) as f:

  with open (backup_file, "w") as w:

    for line in f.readlines():

      if not( line.strip().startswith("#") or line.strip().startswith("//")):

        w.write(line)

parser = c_parser.CParser()

ast = parse_file(backup_file) 

visitor = VariableVisitor()

visitor.visit(ast)

os.remove (backup_file)

with open (args.output_file_name,"w") as f:
   for e in visitor.variables:
      f.writelines(e)
      f.write("\n")



