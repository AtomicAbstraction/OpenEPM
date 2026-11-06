"""Administrator-owned notebook profile; users cannot replace this file."""

c = get_config()  # noqa: F821 - provided by IPython at configuration load
c.HistoryManager.enabled = False
c.InteractiveShell.history_load_length = 0
c.InteractiveShellApp.exec_lines = [
    "import os; os.environ['OPEN_EPM_MANAGED_KERNEL'] = '1'"
]
