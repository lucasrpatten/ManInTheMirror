# Contributing

## Code Guidelines

### Follow PEP Codestyle Guidelines

The Python Enhancement Proposals (PEPs) are a set of guidelines for coding in Python. Please follow these guidelines when contributing to the project.

### Try to use type hints

Please use typing when possible. This helps to improve the readability and maintainability of the code.

### Write docstrings

I know that docstrings are a bit of a pain, but please include them. This will help other contributors understand what your changes do and how to use them.
When writing docstrings use the following format:

```python
def my_function(arg1: str, arg2 = 3: int) -> bool:
    """ This is a concise explanation of what this function does

    Args:
        arg1 (str): This is a concise explanation of arg1
        arg2 (int, optional): This is a concise explanation of arg2. Defaults to 3.

    Returns:
        bool: This is a concise explanation of return value
    """
    # Do something
    return some_boolean
```

### Do not use external libraries

The project should only use built-in Python libraries. This helps to ensure that the project is portable, secure, and safe.

### Test your changes thoroughly

Before submitting a pull request, make sure to test your changes thoroughly for functionality and ease of use.
