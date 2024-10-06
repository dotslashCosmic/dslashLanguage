//Author: dotslashCosmic
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Net.Sockets;
using System.Net.Http;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// Token types
public enum TokenType
{
	Keyword,
	Boolean,
	Identifier,
	Number,
	String,
	Operator,
	Punctuation,
	Comment,
	Whitespace
}

// Token class
public class Token
{
	public TokenType Type { get; }
	public string Value { get; }

	public Token(TokenType type, string value)
	{
		Type = type;
		Value = value;
	}
}

// Lexer
public class Lexer
{
	private static readonly Dictionary<TokenType, string> TokenPatterns = new Dictionary<TokenType, string>
	{
		{
			TokenType.Keyword,
			@"\b(let|fn|type|new|if|elif|else|for|while|try|catch|end|none|and|or|not|give|write|read|loop|i|o|connect|send|close|receive|get|post|alloc|dealloc|clean)\b"
		},
		{
			TokenType.Boolean,
			@"\b(true|false)\b"
		},
		{
			TokenType.Identifier,
			@"\b[a-zA-Z_][a-zA-Z0-9_]*\b"
		},
		{
			TokenType.Number,
			@"\b\d+(\.\d+)?\b"
		},
		{
			TokenType.String,
			@"""[^""]*"""
		},
		{
			TokenType.Operator,
			@"[+\-*/%=<>!]+"
		},
		{
			TokenType.Punctuation,
			@"[{}(),;:\[\].]"
		},
		{
			TokenType.Comment,
			@"#.*|#\*[\s\S]*?\*#"
		},
		{
			TokenType.Whitespace,
			@"\s+"
		}
	};
	public List<Token> Tokenize(string code)
	{
		var tokens = new List<Token>();
		while (!string.IsNullOrEmpty(code))
		{
			Token token = null;
			foreach (var pattern in TokenPatterns)
			{
				var regex = new Regex(pattern.Value);
				var match = regex.Match(code);
				if (match.Success && match.Index == 0)
				{
					token = new Token(pattern.Key, match.Value);
					code = code.Substring(match.Length);
					break;
				}
			}

			if (token == null)
			{
				throw new Exception($"Unexpected character: {code[0]}");
			}

			if (token.Type != TokenType.Whitespace && token.Type != TokenType.Comment)
			{
				tokens.Add(token);
			}
		}

		return tokens;
	}
}

// Abstract Syntax Tree (AST) Node Types
public abstract class ASTNode
{
}

public class ProgramNode : ASTNode
{
	public List<ASTNode> Statements { get; }

	public ProgramNode(List<ASTNode> statements)
	{
		Statements = statements;
	}
}

public class VariableDeclaration : ASTNode
{
	public string Name { get; }
	public Expression Value { get; }

	public VariableDeclaration(string name, Expression value)
	{
		Name = name;
		Value = value;
	}
}

public class FunctionDeclaration : ASTNode
{
	public string Name { get; }
	public List<string> Parameters { get; }
	public List<ASTNode> Body { get; }

	public FunctionDeclaration(string name, List<string> parameters, List<ASTNode> body)
	{
		Name = name;
		Parameters = parameters;
		Body = body;
	}
}

public class ClassDeclaration : ASTNode
{
	public string Name { get; }
	public List<MethodDeclaration> Methods { get; }

	public ClassDeclaration(string name, List<MethodDeclaration> methods)
	{
		Name = name;
		Methods = methods;
	}
}

public class MethodDeclaration : ASTNode
{
	public string Name { get; }
	public List<string> Parameters { get; }
	public List<ASTNode> Body { get; }

	public MethodDeclaration(string name, List<string> parameters, List<ASTNode> body)
	{
		Name = name;
		Parameters = parameters;
		Body = body;
	}
}

public abstract class Expression : ASTNode
{
}

public class ObjectLiteral : Expression
{
	public Dictionary<string, Expression> Properties { get; }

	public ObjectLiteral(Dictionary<string, Expression> properties)
	{
		Properties = properties;
	}
}

public class ReturnStatement : ASTNode
{
	public Expression Expression { get; }

	public ReturnStatement(Expression expression)
	{
		Expression = expression;
	}
}

public class WhileStatement : ASTNode
{
	public Expression Condition { get; }
	public List<ASTNode> Body { get; }

	public WhileStatement(Expression condition, List<ASTNode> body)
	{
		Condition = condition;
		Body = body;
	}
}

public class IfStatement : ASTNode
{
	public Expression Condition { get; }
	public List<ASTNode> ThenBlock { get; }
	public List<(Expression, List<ASTNode>)> ElifBlocks { get; }
	public List<ASTNode> ElseBlock { get; }

	public IfStatement(Expression condition, List<ASTNode> thenBlock, List<(Expression, List<ASTNode>)> elifBlocks, List<ASTNode> elseBlock)
	{
		Condition = condition;
		ThenBlock = thenBlock;
		ElifBlocks = elifBlocks;
		ElseBlock = elseBlock;
	}
}

public class FunctionCall : Expression
{
	public Expression Function { get; }
	public List<Expression> Arguments { get; }

	public FunctionCall(Expression function, List<Expression> arguments)
	{
		Function = function;
		Arguments = arguments;
	}
}

public class MemberAccess : Expression
{
	public Expression Object { get; }
	public Expression Member { get; }

	public MemberAccess(Expression obj, Expression member)
	{
		Object = obj;
		Member = member;
	}
}

public class Identifier : Expression
{
	public string Name { get; }

	public Identifier(string name)
	{
		Name = name;
	}
}

public class BinaryOperation : Expression
{
	public Expression Left { get; }
	public string Operator { get; }
	public Expression Right { get; }

	public BinaryOperation(Expression left, string op, Expression right)
	{
		Left = left;
		Operator = op;
		Right = right;
	}
}

public class Literal : Expression
{
	public object Value { get; }

	public Literal(object value)
	{
		Value = value;
	}
}

public class ListLiteral : Expression
{
	public List<Expression> Elements { get; }

	public ListLiteral(List<Expression> elements)
	{
		Elements = elements;
	}
}

public class LoopStatement : ASTNode
{
	public string Variable { get; }
	public Expression Iterable { get; }
	public List<ASTNode> Body { get; }

	public LoopStatement(string variable, Expression iterable, List<ASTNode> body)
	{
		Variable = variable;
		Iterable = iterable;
		Body = body;
	}
}

public class IOOperation : ASTNode
{
	public string Operation { get; }
	public Expression Value { get; }

	public IOOperation(string operation, Expression value)
	{
		Operation = operation;
		Value = value;
	}
}

public class TryStatement : ASTNode
{
	public List<ASTNode> TryBlock { get; }
	public List<ASTNode> ErrorBlock { get; }

	public TryStatement(List<ASTNode> tryBlock, List<ASTNode> errorBlock)
	{
		TryBlock = tryBlock;
		ErrorBlock = errorBlock;
	}
}

public class NetworkOperation : ASTNode
{
	public string Operation { get; }
	public List<Expression> Arguments { get; }

	public NetworkOperation(string operation, List<Expression> arguments)
	{
		Operation = operation;
		Arguments = arguments;
	}
}

public class MemoryOperation : ASTNode
{
	public string Operation { get; }
	public List<Expression> Arguments { get; }

	public MemoryOperation(string operation, List<Expression> arguments)
	{
		Operation = operation;
		Arguments = arguments;
	}
}

// Parser
public class Parser
{
	private readonly List<Token> tokens;
	private int position;
	public Parser(List<Token> tokens)
	{
		this.tokens = tokens;
		position = 0;
	}

	public ProgramNode Parse()
	{
		var statements = new List<ASTNode>();
		while (position < tokens.Count)
		{
			var statement = ParseStatement();
			if (statement != null)
			{
				statements.Add(statement);
			}
		}

		return new ProgramNode(statements);
	}

	private ASTNode ParseStatement()
	{
		var token = tokens[position];
		if (token.Type == TokenType.Keyword)
		{
			switch (token.Value)
			{
				case "let":
					return ParseVariableDeclaration();
				case "fn":
					return ParseFunctionDeclaration();
				case "type":
					return ParseClassDeclaration();
				case "loop":
					return ParseLoopStatement();
				case "while":
					return ParseWhileStatement();
				case "try":
					return ParseTryStatement();
				case "if":
					return ParseIfStatement();
				case "give":
					position++;
					var expression = ParseExpression();
					return new ReturnStatement(expression);
				case "i":
				case "o":
					return ParseIOOperation();
				case "connect":
				case "send":
				case "close":
				case "receive":
				case "get":
				case "post":
					return ParseNetworkOperation();
				case "alloc":
				case "dealloc":
				case "clean":
					return ParseMemoryOperation();
				default:
					throw new Exception($"Unexpected keyword: {token.Value}");
			}
		}
		else if (token.Type == TokenType.Identifier)
		{
			return ParseExpression();
		}
		else
		{
			throw new Exception($"Unexpected token: {token.Value}");
		}
	}

	private VariableDeclaration ParseVariableDeclaration()
	{
		position++; // Skip 'let'
		var name = tokens[position].Value;
		position++; // Skip variable name
		position++; // Skip '='
		var value = ParseExpression();
		return new VariableDeclaration(name, value);
	}

	private FunctionDeclaration ParseFunctionDeclaration()
	{
		position++; // Skip 'fn'
		var name = tokens[position].Value;
		position++; // Skip function name
		position++; // Skip '('
		var parameters = new List<string>();
		while (tokens[position].Value != ")")
		{
			parameters.Add(tokens[position].Value);
			position++; // Skip parameter
			if (tokens[position].Value == ",")
			{
				position++; // Skip ','
			}
		}

		position++; // Skip ')'
		position++; // Skip '{'
		var body = new List<ASTNode>();
		while (tokens[position].Value != "}")
		{
			body.Add(ParseStatement());
		}

		position++; // Skip '}'
		return new FunctionDeclaration(name, parameters, body);
	}

	private ClassDeclaration ParseClassDeclaration()
	{
		position++; // Skip 'type'
		var name = tokens[position].Value;
		position++; // Skip class name
		position++; // Skip '{'
		var methods = new List<MethodDeclaration>();
		while (tokens[position].Value != "}")
		{
			methods.Add(ParseMethodDeclaration());
		}

		position++; // Skip '}'
		return new ClassDeclaration(name, methods);
	}

	private MethodDeclaration ParseMethodDeclaration()
	{
		var name = tokens[position].Value;
		position++; // Skip method name
		position++; // Skip '('
		var parameters = new List<string>();
		while (tokens[position].Value != ")")
		{
			parameters.Add(tokens[position].Value);
			position++; // Skip parameter
			if (tokens[position].Value == ",")
			{
				position++; // Skip ','
			}
		}

		position++; // Skip ')'
		position++; // Skip '{'
		var body = new List<ASTNode>();
		while (tokens[position].Value != "}")
		{
			body.Add(ParseStatement());
		}

		position++; // Skip '}'
		return new MethodDeclaration(name, parameters, body);
	}

	private WhileStatement ParseWhileStatement()
	{
		position++; // Skip 'while'
		var condition = ParseExpression();
		position++; // Skip 'do'
		var body = new List<ASTNode>();
		while (tokens[position].Value != "end")
		{
			body.Add(ParseStatement());
		}

		position++; // Skip 'end'
		return new WhileStatement(condition, body);
	}

	private IOOperation ParseIOOperation()
	{
		var operation = tokens[position].Value;
		position++; // Skip 'i' or 'o'
		var value = ParseExpression();
		return new IOOperation(operation, value);
	}

	private IfStatement ParseIfStatement()
	{
		position++; // Skip 'if'
		var condition = ParseExpression();
		position++; // Skip 'then'
		var thenBlock = new List<ASTNode>();
		while (tokens[position].Value != "elif" && tokens[position].Value != "else" && tokens[position].Value != "end")
		{
			thenBlock.Add(ParseStatement());
		}

		var elifBlocks = new List<(Expression, List<ASTNode>)>();
		while (tokens[position].Value == "elif")
		{
			position++; // Skip 'elif'
			var elifCondition = ParseExpression();
			position++; // Skip 'then'
			var elifBlock = new List<ASTNode>();
			while (tokens[position].Value != "elif" && tokens[position].Value != "else" && tokens[position].Value != "end")
			{
				elifBlock.Add(ParseStatement());
			}

			elifBlocks.Add((elifCondition, elifBlock));
		}

		var elseBlock = new List<ASTNode>();
		if (tokens[position].Value == "else")
		{
			position++; // Skip 'else'
			while (tokens[position].Value != "end")
			{
				elseBlock.Add(ParseStatement());
			}
		}

		position++; // Skip 'end'
		return new IfStatement(condition, thenBlock, elifBlocks, elseBlock);
	}

	private Expression ParseExpression()
	{
		var left = ParsePrimary();
		while (position < tokens.Count && (tokens[position].Type == TokenType.Operator || tokens[position].Value == "." || tokens[position].Value == "("))
		{
			if (tokens[position].Value == ".")
			{
				position++;
				var right = ParsePrimary();
				left = new MemberAccess(left, right);
			}
			else if (tokens[position].Value == "(")
			{
				position++;
				var args = new List<Expression>();
				while (tokens[position].Value != ")")
				{
					args.Add(ParseExpression());
					if (tokens[position].Value == ",")
					{
						position++;
					}
				}

				position++;
				left = new FunctionCall(left, args);
			}
			else
			{
				var op = tokens[position].Value;
				position++;
				var right = ParsePrimary();
				left = new BinaryOperation(left, op, right);
			}
		}

		return left;
	}

	private Expression ParsePrimary()
	{
		var token = tokens[position];
		switch (token.Type)
		{
			case TokenType.Number:
				position++;
				return new Literal(double.TryParse(token.Value, out double numValue) ? (object)numValue : int.Parse(token.Value));
			case TokenType.String:
				position++;
				return new Literal(token.Value.Trim('"'));
			case TokenType.Boolean:
				position++;
				return new Literal(token.Value == "true");
			case TokenType.Identifier:
				position++;
				return new Identifier(token.Value);
			case TokenType.Punctuation when token.Value == "(":
				position++;
				var expr = ParseExpression();
				if (tokens[position].Value != ")")
				{
					throw new Exception("Expected ')'");
				}

				position++;
				return expr;
			case TokenType.Punctuation when token.Value == "[":
				position++;
				var elements = new List<Expression>();
				while (tokens[position].Value != "]")
				{
					elements.Add(ParseExpression());
					if (tokens[position].Value == ",")
					{
						position++;
					}
				}

				position++;
				return new ListLiteral(elements);
			case TokenType.Punctuation when token.Value == "{":
				position++;
				var properties = new Dictionary<string, Expression>();
				while (tokens[position].Value != "}")
				{
					var key = tokens[position].Value;
					position++; // Skip key
					if (tokens[position].Value != ":")
					{
						throw new Exception("Expected ':'");
					}

					position++; // Skip ':'
					var value = ParseExpression();
					properties[key] = value;
					if (tokens[position].Value == ",")
					{
						position++;
					}
				}

				position++;
				return new ObjectLiteral(properties);
			default:
				throw new Exception($"Unexpected token: {token.Value}");
		}
	}

	private LoopStatement ParseLoopStatement()
	{
		position++; // Skip 'loop'
		var variable = tokens[position].Value;
		position++; // Skip variable name
		position++; // Skip '='
		var iterable = ParseExpression();
		position++; // Skip 'do'
		var body = new List<ASTNode>();
		while (tokens[position].Value != "end")
		{
			body.Add(ParseStatement());
		}

		position++; // Skip 'end'
		return new LoopStatement(variable, iterable, body);
	}

	private TryStatement ParseTryStatement()
	{
		position++; // Skip 'try'
		var tryBlock = new List<ASTNode>();
		while (tokens[position].Value != "catch")
		{
			tryBlock.Add(ParseStatement());
		}

		position++; // Skip 'catch'
		var errorBlock = new List<ASTNode>();
		while (tokens[position].Value != "end")
		{
			errorBlock.Add(ParseStatement());
		}

		position++; // Skip 'end'
		return new TryStatement(tryBlock, errorBlock);
	}
	private ASTNode ParseNetworkOperation()
	{
		position++; // Skip the network operation keyword
		var operation = tokens[position - 1].Value;
		var arguments = new List<Expression>();

		while (tokens[position].Type != TokenType.Keyword && tokens[position].Type != TokenType.Punctuation)
		{
			arguments.Add(ParseExpression());
			if (tokens[position].Value == ",")
			{
				position++; // Skip ','
			}
		}

		return new NetworkOperation(operation, arguments);
	}

	private ASTNode ParseMemoryOperation()
	{
		position++; // Skip the memory operation keyword
		var operation = tokens[position - 1].Value;
		var arguments = new List<Expression>();

		while (tokens[position].Type != TokenType.Keyword && tokens[position].Type != TokenType.Punctuation)
		{
			arguments.Add(ParseExpression());
			if (tokens[position].Value == ",")
			{
				position++; // Skip ','
			}
		}

		return new MemoryOperation(operation, arguments);
	}
}

// Interpreter
public class Interpreter
{
	private readonly ProgramNode ast;
	private Dictionary<string, object> environment;
	private TcpClient tcpClient;
	private HttpClient httpClient = new HttpClient();
	private Dictionary<object, IntPtr> memoryAllocations = new Dictionary<object, IntPtr>();

	public Interpreter(ProgramNode ast, Dictionary<string, object> environment = null)
	{
		this.ast = ast;
		this.environment = environment ?? new Dictionary<string, object>();
	}

	public void Execute()
	{
		ExecuteStatements(ast.Statements);
	}

	private void ExecuteStatements(List<ASTNode> statements)
	{
		foreach (var statement in statements)
		{
			ExecuteStatement(statement);
		}
	}

	private void ExecuteStatement(ASTNode statement)
	{
		switch (statement)
		{
			case VariableDeclaration varDecl:
				environment[varDecl.Name] = EvaluateExpression(varDecl.Value);
				break;
			case FunctionDeclaration funcDecl:
				environment[funcDecl.Name] = funcDecl;
				break;
			case ClassDeclaration classDecl:
				environment[classDecl.Name] = classDecl;
				break;
			case LoopStatement loopStmt:
				ExecuteLoop(loopStmt);
				break;
			case IOOperation ioOp:
				ExecuteIO(ioOp);
				break;
			case TryStatement tryStmt:
				ExecuteTry(tryStmt);
				break;
			case IfStatement ifStmt:
				ExecuteIf(ifStmt);
				break;
			case ReturnStatement returnStmt:
				// Handle return statement if needed
				break;
			default:
				throw new Exception($"Unknown statement type: {statement.GetType()}");
		}
	}

	private void ExecuteLoop(LoopStatement loopStmt)
	{
		var iterable = EvaluateExpression(loopStmt.Iterable) as IEnumerable<object>;
		foreach (var item in iterable)
		{
			environment[loopStmt.Variable] = item;
			ExecuteStatements(loopStmt.Body);
		}
	}

	private void ExecuteIO(IOOperation ioOp)
	{
		var value = EvaluateExpression(ioOp.Value);
		if (ioOp.Operation == "i")
		{
			Console.Write(value);
			var input = Console.ReadLine();
			environment["user_input"] = input;
		}
		else if (ioOp.Operation == "o")
		{
			Console.WriteLine(value);
		}
	}

	private void ExecuteTry(TryStatement tryStmt)
	{
		try
		{
			ExecuteStatements(tryStmt.TryBlock);
		}
		catch
		{
			ExecuteStatements(tryStmt.ErrorBlock);
		}
	}

	private void ExecuteIf(IfStatement ifStmt)
	{
		if (Convert.ToBoolean(EvaluateExpression(ifStmt.Condition)))
		{
			ExecuteStatements(ifStmt.ThenBlock);
		}
		else
		{
			foreach (var(condition, block)in ifStmt.ElifBlocks)
			{
				if (Convert.ToBoolean(EvaluateExpression(condition)))
				{
					ExecuteStatements(block);
					return;
				}
			}

			ExecuteStatements(ifStmt.ElseBlock);
		}
	}

	private void ExecuteNetworkOperation(NetworkOperation netOp)
	{
		switch (netOp.Operation)
		{
			case "connect":
				var address = EvaluateExpression(netOp.Arguments[0]).ToString();
				var port = Convert.ToInt32(EvaluateExpression(netOp.Arguments[1]));
				tcpClient = new TcpClient(address, port);
				Console.WriteLine($"Connected to {address}:{port}");
				break;
			case "send":
				var dataToSend = EvaluateExpression(netOp.Arguments[0]).ToString();
				var stream = tcpClient.GetStream();
				var data = System.Text.Encoding.ASCII.GetBytes(dataToSend);
				stream.Write(data, 0, data.Length);
				Console.WriteLine($"Sent data: {dataToSend}");
				break;
			case "receive":
				var buffer = new byte[1024];
				var bytesRead = tcpClient.GetStream().Read(buffer, 0, buffer.Length);
				var receivedData = System.Text.Encoding.ASCII.GetString(buffer, 0, bytesRead);
				environment["response"] = receivedData;
				Console.WriteLine($"Received data: {receivedData}");
				break;
			case "close":
				tcpClient.Close();
				Console.WriteLine("Connection closed");
				break;
			case "get":
				var url = EvaluateExpression(netOp.Arguments[0]).ToString();
				var response = httpClient.GetStringAsync(url).Result;
				Console.WriteLine($"HTTP GET Response: {response}");
				break;
			case "post":
				var postUrl = EvaluateExpression(netOp.Arguments[0]).ToString();
				var postData = EvaluateExpression(netOp.Arguments[1]).ToString();
				var content = new StringContent(postData, System.Text.Encoding.UTF8, "application/json");
				var postResponse = httpClient.PostAsync(postUrl, content).Result;
				Console.WriteLine($"HTTP POST Response: {postResponse.Content.ReadAsStringAsync().Result}");
				break;
			default:
				throw new Exception($"Unknown network operation: {netOp.Operation}");
		}
	}

	private void ExecuteMemoryOperation(MemoryOperation memOp)
	{
		switch (memOp.Operation)
		{
			case "alloc":
				var size = Convert.ToInt32(EvaluateExpression(memOp.Arguments[1]));
				var allocatedMemory = Marshal.AllocHGlobal(size);
				memoryAllocations[memOp.Arguments[0]] = allocatedMemory;
				Console.WriteLine($"Allocated {size} bytes");
				break;
			case "write":
				var pointer = memoryAllocations[memOp.Arguments[0]];
				var offset = Convert.ToInt32(EvaluateExpression(memOp.Arguments[1]));
				var value = Convert.ToInt32(EvaluateExpression(memOp.Arguments[2]));
				Marshal.WriteInt32(pointer, offset, value);
				Console.WriteLine($"Wrote {value} to memory at offset {offset}");
				break;
			case "read":
				var readPointer = memoryAllocations[memOp.Arguments[0]];
				var readOffset = Convert.ToInt32(EvaluateExpression(memOp.Arguments[1]));
				var readValue = Marshal.ReadInt32(readPointer, readOffset);
				environment["value"] = readValue;
				Console.WriteLine($"Read value {readValue} from memory at offset {readOffset}");
				break;
			case "dealloc":
				foreach (var arg in memOp.Arguments)
				{
					var deallocPointer = memoryAllocations[arg];
					Marshal.FreeHGlobal(deallocPointer);
					Console.WriteLine("Deallocated memory");
				}
				break;
			case "clean":
				foreach (var ptr in memoryAllocations.Values)
				{
					Marshal.FreeHGlobal(ptr);
				}
				memoryAllocations.Clear();
				Console.WriteLine("Performed cleaning operation");
				break;
			default:
				throw new Exception($"Unknown memory operation: {memOp.Operation}");
		}
	}

	private object EvaluateExpression(Expression expr)
	{
		switch (expr)
		{
			case Literal literal:
				return literal.Value;
			case Identifier identifier:
				return environment[identifier.Name];
			case BinaryOperation binaryOp:
				var left = EvaluateExpression(binaryOp.Left);
				var right = EvaluateExpression(binaryOp.Right);
				return EvaluateBinaryOperation(left, binaryOp.Operator, right);
			case FunctionCall funcCall:
				return ExecuteFunctionCall(funcCall);
			case MemberAccess memberAccess:
				var obj = EvaluateExpression(memberAccess.Object);
				var member = EvaluateExpression(memberAccess.Member);
				return AccessMember(obj, member);
			case ListLiteral listLiteral:
				var elements = new List<object>();
				foreach (var element in listLiteral.Elements)
				{
					elements.Add(EvaluateExpression(element));
				}

				return elements;
			case ObjectLiteral objectLiteral:
				var properties = new Dictionary<string, object>();
				foreach (var prop in objectLiteral.Properties)
				{
					properties[prop.Key] = EvaluateExpression(prop.Value);
				}

				return properties;
			default:
				throw new Exception($"Unknown expression type: {expr.GetType()}");
		}
	}

	private object EvaluateBinaryOperation(object left, string op, object right)
	{
		switch (op)
		{
			case "+":
				return (double)left + (double)right;
			case "-":
				return (double)left - (double)right;
			case "*":
				return (double)left * (double)right;
			case "/":
				return (double)left / (double)right;
			case "%":
				return (double)left % (double)right;
			case "==":
				return Equals(left, right);
			case "!=":
				return !Equals(left, right);
			case "<":
				return (double)left < (double)right;
			case ">":
				return (double)left > (double)right;
			case "<=":
				return (double)left <= (double)right;
			case ">=":
				return (double)left >= (double)right;
			default:
				throw new Exception($"Unknown operator: {op}");
		}
	}

	private object ExecuteFunctionCall(FunctionCall funcCall)
	{
		if (funcCall.Function is Identifier funcIdentifier && environment[funcIdentifier.Name] is FunctionDeclaration funcDecl)
		{
			var localEnv = new Dictionary<string, object>(environment);
			for (int i = 0; i < funcDecl.Parameters.Count; i++)
			{
				localEnv[funcDecl.Parameters[i]] = EvaluateExpression(funcCall.Arguments[i]);
			}

			var interpreter = new Interpreter(new ProgramNode(funcDecl.Body), localEnv);
			interpreter.Execute();
			return localEnv.ContainsKey("return") ? localEnv["return"] : null;
		}

		throw new Exception("Function not found or invalid function call.");
	}

	private object AccessMember(object obj, object member)
	{
		if (obj is Dictionary<string, object> dict && member is string memberName)
		{
			return dict[memberName];
		}

		throw new Exception("Invalid member access.");
	}
}

// Main Program to run the interpreter
class Program
{
	static void Main(string[] args)
	{
		string filePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
		string hash = GetFileHash(filePath);
		string build = $@"
DSlash Interpreter
Author: dotslashCosmic
Version 0.1 (Build: {GenerateBuildString(hash)})
";
		Console.WriteLine(build);
		string code = File.ReadAllText("example.dslash");
		var lexer = new Lexer();
		var tokens = lexer.Tokenize(code);
		var parser = new Parser(tokens);
		var ast = parser.Parse();
		var interpreter = new Interpreter(ast);
		interpreter.Execute();
	}

	static string GetFileHash(string filePath)
	{
		using (var sha256 = SHA256.Create())
		{
			using (var stream = File.OpenRead(filePath))
			{
				byte[] hashBytes = sha256.ComputeHash(stream);
				return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
			}
		}
	}

// TODO Fix so its 4 pseudo random words based on the hash
	static string GenerateBuildString(string hash)
	{
		string[] buildWords = {
			"Asteroid", "Astrobiology", "Astrophysics", "Atomic", "Aurora", "BlackHole", "Celestial",
			"Comet", "Continuum", "Corona", "Cosmic", "Cosmology", "DarkMatter", "Eclipse", 
			"EventHorizon", "Exoplanet", "Exosphere", "Extragalactic", "Galactic", "GammaRay", 
			"Gravitational", "Graviton", "Heliosphere", "Hypernova", "Intergalactic", "LightYear", 
			"Lunar", "Magnetosphere", "Meteorite", "Microlensing", "Moon", "Multiverse", "Nebula", 
			"Neutron", "OortCloud", "Orbit", "Parallax", "Parsec", "Planet", "Protostar", "Pulsar", 
			"Quasar", "Radiation", "Redshift", "Rocket", "Singularity", "Solar", "Space", "Stardust", 
			"Stellar", "Supernova", "Tachyon", "Time", "Ultraviolet", "Wormhole", "XRay", "Zenith"
		};

		int seed = 0;
		foreach (char c in hash)
		{
			seed = (seed * 31 + c) % buildWords.Length;
		}

		Random random = new Random(seed);
		StringBuilder buildString = new StringBuilder();
		HashSet<int> usedIndices = new HashSet<int>();

		for (int i = 0; i < 4; i++)
		{
			int index;
			do
			{
				index = random.Next(buildWords.Length);
			} while (usedIndices.Contains(index));

			usedIndices.Add(index);
			buildString.Append(buildWords[index]);
		}

		return buildString.ToString();
	}
}
