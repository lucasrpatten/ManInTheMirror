# Contribution Guidlines and Ways To Contribute

## Report Bugs

If you find a bug in ManInTheMirror, please report it in the issue tracker. Be sure to include as much information as possible, such as the steps to reproduce the bug and the expected behavior.

## Suggest Features

If you have a suggestion for a new feature, please open an issue in the issue tracker. Be sure to describe the feature in detail and explain why you think it would be useful.

## Promoting the Project

You can help promote ManInTheMirror by writing blog posts about it, tweeting about it, or talking about it with your friends and colleagues. This can help raise awareness of the project and attract new users.

## Code Guidelines

### Follow PEP Codestyle Guidelines

The Python Enhancement Proposals (PEPs) are a set of guidelines for coding in Python. Please follow these guidelines when contributing to the project. Keep the codestyle consistent to the rest of the project

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

## Submitting a Pull Request

### Pull Requests

If a pull request contains multiple changes or features, it can be challenging for reviewers to provide feedback on all aspects of the change. Because of this, please submit seperate pull requests for each new feature or major change.

### Commit Messages

When making a commit, make sure to use a title that is both informative and concise. Additionally, provide a detailed commit message that summarizes your changes and provides a clear description of what was modified, added, or removed in your commit. This will help other contributors understand your changes and their purpose, and make it easier to review and maintain the project.

Here's a sample commit message:

```commit
Commit Title: Add function to calculate area of a circle

Commit Message:

In this commit, I added a new function to the project that calculates the area of a circle. The function takes the radius of the circle as an input parameter and returns the area. I also added a test function to ensure that the area is calculated correctly. The new function follows the project's code style and is well-documented with clear parameter and return value descriptions. This new feature will make it easier for users to calculate the area of a circle within the project.
```
