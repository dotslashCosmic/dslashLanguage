import re

# Token types
TOKEN_TYPES = {
    'KEYWORD': r'\b(let|fn|type|new|if|elif|else|for|while|try|catch|end|none|and|or|not|give|write|read|loop|i|o)\b',
    'BOOLEAN': r'\b(true|false)\b',
    'IDENTIFIER': r'\b[a-zA-Z_][a-zA-Z0-9_]*\b',
    'NUMBER': r'\b\d+(\.\d+)?\b',
    'STRING': r'"[^"]*"',
    'OPERATOR': r'[+\-*/%=<>!]+',
    'PUNCTUATION': r'[{}(),;:\[\].]',
    'COMMENT': r'#.*|#\*[\s\S]*?\*#',
    'WHITESPACE': r'\s+',
}

# Tokenizer
def tokenize(code):
    tokens = []
    while code:
        match = None
        for token_type, pattern in TOKEN_TYPES.items():
            regex = re.compile(pattern)
            match = regex.match(code)
            if match:
                if token_type != 'WHITESPACE' and token_type != 'COMMENT':
                    tokens.append((token_type, match.group(0)))
                code = code[match.end():]
                break
        if not match:
            print(f"Remaining code: {code}")  # Debugging information
            raise SyntaxError(f"Unexpected character: {code[0]}")
    return tokens

# AST Node Types
class ASTNode:
    pass

class Program(ASTNode):
    def __init__(self, statements):
        self.statements = statements

class VariableDeclaration(ASTNode):
    def __init__(self, name, value):
        self.name = name
        self.value = value

class FunctionDeclaration(ASTNode):
    def __init__(self, name, params, body):
        self.name = name
        self.params = params
        self.body = body

class ClassDeclaration(ASTNode):
    def __init__(self, name, methods):
        self.name = name
        self.methods = methods

class MethodDeclaration(ASTNode):
    def __init__(self, name, params, body):
        self.name = name
        self.params = params
        self.body = body

class Expression(ASTNode):
    pass

class ObjectLiteral(Expression):
    def __init__(self, properties):
        self.properties = properties

class ReturnStatement(ASTNode):
    def __init__(self, expression):
        self.expression = expression

class WhileStatement(ASTNode):
    def __init__(self, condition, body):
        self.condition = condition
        self.body = body

class IfStatement(ASTNode):
    def __init__(self, condition, then_block, elif_blocks, else_block):
        self.condition = condition
        self.then_block = then_block
        self.elif_blocks = elif_blocks
        self.else_block = else_block

class FunctionCall(Expression):
    def __init__(self, function, args):
        self.function = function
        self.args = args

class MemberAccess(Expression):
    def __init__(self, object, member):
        self.object = object
        self.member = member

class Identifier(Expression):
    def __init__(self, name):
        self.name = name

class BinaryOperation(Expression):
    def __init__(self, left, operator, right):
        self.left = left
        self.operator = operator
        self.right = right

class Literal(Expression):
    def __init__(self, value):
        self.value = value

class ListLiteral(Expression):
    def __init__(self, elements):
        self.elements = elements

class LoopStatement(ASTNode):
    def __init__(self, variable, iterable, body):
        self.variable = variable
        self.iterable = iterable
        self.body = body

class IOOperation(ASTNode):
    def __init__(self, operation, value):
        self.operation = operation
        self.value = value

class TryStatement(ASTNode):
    def __init__(self, try_block, error_block):
        self.try_block = try_block
        self.error_block = error_block

# Parser
class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def parse(self):
        statements = []
        while self.pos < len(self.tokens):
            statements.append(self.parse_statement())
        return Program(statements)

    def parse_statement(self):
        token_type, token_value = self.tokens[self.pos]
        print(f"Debug (parse_statement): token_type={token_type}, token_value={token_value}")  # Debugging information
        if token_type == 'KEYWORD' and token_value == 'let':
            return self.parse_variable_declaration()
        elif token_type == 'KEYWORD' and token_value == 'fn':
            return self.parse_function_declaration()
        elif token_type == 'KEYWORD' and token_value == 'give':
            self.pos += 1
            expression = self.parse_expression()
            return ReturnStatement(expression)
        elif token_type == 'KEYWORD' and token_value == 'type':
            return self.parse_class_declaration()
        elif token_type == 'KEYWORD' and token_value == 'loop':
            return self.parse_loop_statement()
        elif token_type == 'KEYWORD' and token_value == 'while':
            return self.parse_while_statement()
        elif token_type == 'KEYWORD' and token_value in ['i', 'o']:
            return self.parse_io_operation()
        elif token_type == 'KEYWORD' and token_value == 'try':
            return self.parse_try_statement()
        elif token_type == 'KEYWORD' and token_value == 'if':
            return self.parse_if_statement()
        elif token_type == 'IDENTIFIER':
            return self.parse_expression()
        else:
            raise SyntaxError(f"Unexpected token: {token_value}")

    def parse_variable_declaration(self):
        self.pos += 1  # Skip 'let'
        name = self.tokens[self.pos][1]
        print(f"Debug (parse_variable_declaration): name={name}")  # Debugging information
        self.pos += 1  # Skip variable name
        self.pos += 1  # Skip '='
        value = self.parse_expression()
        print(f"Debug (parse_variable_declaration): value={value}")  # Debugging information
        return VariableDeclaration(name, value)

    def parse_function_declaration(self):
        self.pos += 1  # Skip 'fn'
        name = self.tokens[self.pos][1]
        self.pos += 1  # Skip function name
        self.pos += 1  # Skip '('
        params = []
        while self.tokens[self.pos][1] != ')':
            params.append(self.tokens[self.pos][1])
            self.pos += 1
            if self.tokens[self.pos][1] == ',':
                self.pos += 1
        self.pos += 1  # Skip ')'
        self.pos += 1  # Skip '{'
        body = []
        while self.tokens[self.pos][1] != '}':
            body.append(self.parse_statement())
        self.pos += 1  # Skip '}'
        return FunctionDeclaration(name, params, body)

    def parse_class_declaration(self):
        self.pos += 1  # Skip 'type'
        name = self.tokens[self.pos][1]
        self.pos += 1  # Skip class name
        self.pos += 1  # Skip '{'
        methods = []
        while self.tokens[self.pos][1] != '}':
            methods.append(self.parse_method_declaration())
        self.pos += 1  # Skip '}'
        return ClassDeclaration(name, methods)

    def parse_method_declaration(self):
        name = self.tokens[self.pos][1]
        self.pos += 1  # Skip method name
        self.pos += 1  # Skip '('
        params = []
        while self.tokens[self.pos][1] != ')':
            params.append(self.tokens[self.pos][1])
            self.pos += 1
            if self.tokens[self.pos][1] == ',':
                self.pos += 1
        self.pos += 1  # Skip ')'
        self.pos += 1  # Skip '{'
        body = []
        while self.tokens[self.pos][1] != '}':
            body.append(self.parse_statement())
        self.pos += 1  # Skip '}'
        return MethodDeclaration(name, params, body)

    def parse_while_statement(self):
        self.pos += 1  # Skip 'while'
        condition = self.parse_expression()
        self.pos += 1  # Skip 'do'
        body = []
        while self.tokens[self.pos][1] != 'end':
            body.append(self.parse_statement())
        self.pos += 1  # Skip 'end'
        return WhileStatement(condition, body)

    def parse_io_operation(self):
        operation = self.tokens[self.pos][1]
        self.pos += 1  # Skip 'i' or 'o'
        value = self.parse_expression()
        return IOOperation(operation, value)

    def parse_if_statement(self):
        self.pos += 1  # Skip 'if'
        condition = self.parse_expression()
        self.pos += 1  # Skip 'then'
        then_block = []
        while self.tokens[self.pos][1] not in ['elif', 'else', 'end']:
            then_block.append(self.parse_statement())
        elif_blocks = []
        while self.tokens[self.pos][1] == 'elif':
            self.pos += 1  # Skip 'elif'
            elif_condition = self.parse_expression()
            self.pos += 1  # Skip 'then'
            elif_block = []
            while self.tokens[self.pos][1] not in ['elif', 'else', 'end']:
                elif_block.append(self.parse_statement())
            elif_blocks.append((elif_condition, elif_block))
        else_block = []
        if self.tokens[self.pos][1] == 'else':
            self.pos += 1  # Skip 'else'
            while self.tokens[self.pos][1] != 'end':
                else_block.append(self.parse_statement())
        self.pos += 1  # Skip 'end'
        return IfStatement(condition, then_block, elif_blocks, else_block)

    def parse_expression(self):
        left = self.parse_primary()
        while self.pos < len(self.tokens) and (self.tokens[self.pos][0] == 'OPERATOR' or self.tokens[self.pos][1] == '.' or self.tokens[self.pos][1] == '('):
            if self.tokens[self.pos][1] == '.':
                self.pos += 1
                right = self.parse_primary()
                left = MemberAccess(left, right)
            elif self.tokens[self.pos][1] == '(':
                self.pos += 1
                args = []
                while self.tokens[self.pos][1] != ')':
                    args.append(self.parse_expression())
                    if self.tokens[self.pos][1] == ',':
                        self.pos += 1
                if self.tokens[self.pos][1] != ')':
                    raise SyntaxError("Expected ')'")
                self.pos += 1
                left = FunctionCall(left, args)
            else:
                operator = self.tokens[self.pos][1]
                self.pos += 1
                right = self.parse_primary()
                left = BinaryOperation(left, operator, right)
        return left

    def parse_primary(self):
        token_type, token_value = self.tokens[self.pos]
        if token_type == 'NUMBER':
            self.pos += 1
            return Literal(float(token_value)) if '.' in token_value else Literal(int(token_value))
        elif token_type == 'STRING':
            self.pos += 1
            return Literal(token_value.strip('"'))
        elif token_type == 'BOOLEAN':
            self.pos += 1
            return Literal(True if token_value == 'true' else False)
        elif token_type == 'IDENTIFIER':
            self.pos += 1
            return Identifier(token_value)
        elif token_type == 'PUNCTUATION' and token_value == '(':
            self.pos += 1
            expr = self.parse_expression()
            if self.tokens[self.pos][1] != ')':
                raise SyntaxError("Expected ')'")
            self.pos += 1
            return expr
        elif token_type == 'PUNCTUATION' and token_value == '[':
            self.pos += 1
            elements = []
            while self.tokens[self.pos][1] != ']':
                elements.append(self.parse_expression())
                if self.tokens[self.pos][1] == ',':
                    self.pos += 1
            if self.tokens[self.pos][1] != ']':
                raise SyntaxError("Expected ']'")
            self.pos += 1
            return ListLiteral(elements)
        elif token_type == 'PUNCTUATION' and token_value == '{':
            self.pos += 1
            properties = {}
            while self.tokens[self.pos][1] != '}':
                key = self.tokens[self.pos][1]
                self.pos += 1  # Skip key
                if self.tokens[self.pos][1] != ':':
                    raise SyntaxError("Expected ':'")
                self.pos += 1  # Skip ':'
                value = self.parse_expression()
                properties[key] = value
                if self.tokens[self.pos][1] == ',':
                    self.pos += 1
            if self.tokens[self.pos][1] != '}':
                raise SyntaxError("Expected '}'")
            self.pos += 1
            return ObjectLiteral(properties)
        else:
            raise SyntaxError(f"Unexpected token: {token_value}")

# Interpreter
class Interpreter:
    def __init__(self, ast):
        self.ast = ast

    def execute(self):
        self.environment = {}
        self.execute_statements(self.ast.statements)

    def execute_statements(self, statements):
        for statement in statements:
            self.execute_statement(statement)

    def execute_statement(self, statement):
        if isinstance(statement, VariableDeclaration):
            self.environment[statement.name] = self.evaluate_expression(statement.value)
        elif isinstance(statement, FunctionDeclaration):
            self.environment[statement.name] = statement
        elif isinstance(statement, ClassDeclaration):
            self.environment[statement.name] = statement
        elif isinstance(statement, LoopStatement):
            self.execute_loop(statement)
        elif isinstance(statement, IOOperation):
            self.execute_io(statement)
        elif isinstance(statement, TryStatement):
            self.execute_try(statement)
        else:
            raise RuntimeError(f"Unknown statement type: {type(statement)}")

    def execute_loop(self, statement):
        iterable = self.evaluate_expression(statement.iterable)
        for item in iterable:
            self.environment[statement.variable] = item
            self.execute_statements(statement.body)

    def execute_io(self, statement):
        if statement.operation == 'i':
            value = input(statement.value)
            self.environment['user_input'] = value
        elif statement.operation == 'o':
            value = self.evaluate_expression(statement.value)
            print(value)

    def execute_try(self, statement):
        try:
            self.execute_statements(statement.try_block)
        except Exception as e:
            self.execute_statements(statement.error_block)

    def evaluate_expression(self, expression):
        if isinstance(expression, Literal):
            return expression.value
        elif isinstance(expression, Identifier):
            return self.environment[expression.name]
        elif isinstance(expression, BinaryOperation):
            left = self.evaluate_expression(expression.left)
            right = self.evaluate_expression(expression.right)
            if expression.operator == '+':
                return left + right
            elif expression.operator == '-':
                return left - right
            elif expression.operator == '*':
                return left * right
            elif expression.operator == '/':
                return left / right
            elif expression.operator == '%':
                return left % right
            elif expression.operator == '==':
                return left == right
            elif expression.operator == '!=':
                return left != right
            elif expression.operator == '<':
                return left < right
            elif expression.operator == '>':
                return left > right
            elif expression.operator == '<=':
                return left <= right
            elif expression.operator == '>=':
                return left >= right
            else:
                raise RuntimeError(f"Unknown operator: {expression.operator}")
        else:
            raise RuntimeError(f"Unknown expression type: {type(expression)}")

if __name__ == '__main__':
    with open('example.dslash', 'r') as file:
        code = file.read()
    tokens = tokenize(code)
    parser = Parser(tokens)
    ast = parser.parse()
    interpreter = Interpreter(ast)
    interpreter.execute()

def parse_statement(self):
    token_type, token_value = self.tokens[self.pos]
    if token_type == 'KEYWORD' and token_value == 'let':
        return self.parse_variable_declaration()
    elif token_type == 'KEYWORD' and token_value == 'fn':
        return self.parse_function_declaration()
    elif token_type == 'KEYWORD' and token_value == 'type':
        return self.parse_class_declaration()
    elif token_type == 'KEYWORD' and token_value == 'loop':
        return self.parse_loop_statement()
    elif token_type == 'KEYWORD' and token_value in ['i', 'o']:
        return self.parse_io_operation()
    elif token_type == 'KEYWORD' and token_value == 'try':
        return self.parse_try_statement()
    elif token_value == '//':
        # Skip the comment token and the rest of the line
        while self.pos < len(self.tokens) and self.tokens[self.pos][0] != 'NEWLINE':
            self.pos += 1
        self.pos += 1  # Skip the newline token
        return None  # No statement to return for a comment
    else:
        raise SyntaxError(f"Unexpected token: {token_value}")
