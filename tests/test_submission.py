import pytest
from backend.modules.submission import CodeSubmissionModule

def test_language_detection():
    py_code = "def calculate_sum(a, b):\n    return a + b\n"
    assert CodeSubmissionModule.detect_language(py_code) == "python"

    java_code = "public class Calculator {\n    public int add(int a, int b) {\n        return a + b;\n    }\n}\n"
    assert CodeSubmissionModule.detect_language(java_code) == "java"

    # Filename override
    assert CodeSubmissionModule.detect_language("x = 10", filename="Test.java") == "java"
    assert CodeSubmissionModule.detect_language("System.out.println()", filename="script.py") == "python"

def test_python_valid_syntax_and_ast():
    py_code = """
import os
import math

class DataProcessor:
    def process(self, items):
        total = 0
        for item in items:
            if item > 0:
                total += item
            else:
                total -= item
        return total
"""
    result = CodeSubmissionModule.validate_code(py_code, language="python")
    assert result.is_valid is True
    assert result.language == "python"
    assert result.line_count > 5
    assert result.ast_summary["function_count"] == 1
    assert result.ast_summary["class_count"] == 1
    assert "os" in result.ast_summary["imports"]
    assert result.cyclomatic_complexity >= 3

def test_python_syntax_error():
    broken_code = """
def faulty_func(x)
    return x * 2
"""
    result = CodeSubmissionModule.validate_code(broken_code, language="python")
    assert result.is_valid is False
    assert result.error_line == 2
    assert "SyntaxError" in result.error_message

def test_java_valid_syntax():
    java_code = """
package com.demo;

public class OrderService {
    public boolean processOrder(String orderId) {
        if (orderId != null && !orderId.isEmpty()) {
            return true;
        }
        return false;
    }
}
"""
    result = CodeSubmissionModule.validate_code(java_code, language="java")
    assert result.is_valid is True
    assert result.language == "java"
    assert result.ast_summary["class_count"] == 1
    assert result.cyclomatic_complexity >= 2

def test_java_unbalanced_delimiters():
    broken_java = """
public class BrokenApp {
    public void run() {
        if (true) {
            System.out.println("Missing closing brace");
    }
}
"""
    result = CodeSubmissionModule.validate_code(broken_java, language="java")
    assert result.is_valid is False
    assert "Unclosed delimiter" in result.error_message or "Mismatched" in result.error_message

def test_empty_submission():
    result = CodeSubmissionModule.validate_code("   ", language="python")
    assert result.is_valid is False
    assert "empty" in result.error_message.lower()

def test_automatic_language_identification_without_language_param():
    py_code = "def greet(name):\n    return f'Hello, {name}'\n"
    # Call validate_code without specifying language or specifying 'auto'
    res_py = CodeSubmissionModule.validate_code(py_code)
    assert res_py.language == "python"
    assert res_py.is_valid is True

    java_code = "public class Hello {\n    public static void main(String[] args) {\n        System.out.println(\"Hi\");\n    }\n}\n"
    res_java = CodeSubmissionModule.validate_code(java_code, language="auto")
    assert res_java.language == "java"
    assert res_java.is_valid is True

def test_auto_detection_with_default_filename_placeholders():
    # If the UI has main.py open as default, but Java code is submitted, it should detect Java
    java_code = "public class AuthHandler {\n    public boolean check(String t) {\n        return t != null;\n    }\n}\n"
    assert CodeSubmissionModule.detect_language(java_code, filename="main.py") == "java"
    result = CodeSubmissionModule.validate_code(java_code, language="auto", filename="main.py")
    assert result.language == "java"
    assert result.filename == "Main.java"
    assert result.is_valid is True

    # If the UI has Main.java open as default, but Python code is submitted, it should detect Python
    py_code = "def check_token(token):\n    return token is not None\n"
    assert CodeSubmissionModule.detect_language(py_code, filename="Main.java") == "python"
    result_py = CodeSubmissionModule.validate_code(py_code, language="auto", filename="Main.java")
    assert result_py.language == "python"
    assert result_py.filename == "main.py"
    assert result_py.is_valid is True


