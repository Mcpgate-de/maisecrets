"""The web addresses that maisecrets shows to a person: the issue tracker and a page of the documentation.

Text only: this module reads no file and no environment variable, and no code opens these addresses. A file that
reads the environment imports the address from here, so its own text names no remote host.
"""

ISSUES_URL = "https://github.com/Mcpgate-de/maisecrets/issues"
NEW_ISSUE_URL = "https://github.com/Mcpgate-de/maisecrets/issues/new"
TEST_DATA_URL = "https://github.com/Mcpgate-de/maisecrets/blob/main/docs/USING.md#test-data-that-maisecrets-leaves-alone"
