import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import ast
import os

# Dangerous functions
DANGEROUS_FUNCTIONS = {
    "eval",
    "exec",
    "os.system",
    "subprocess.Popen",
    "open",
    "shutil.rmtree",
    "os.remove",
    "pickle.load",
    "pickle.loads",
    "marshal.load",
    "marshal.loads",
}

# Example of code with vulnerabilities
DANGEROUS_CODE = """# Example of code with vulnerabilities
import os
eval('print("Hello, World!")')
os.system('ls')
"""


class CodeAnalyzer:
    def __init__(self, dangerous_functions):
        self.dangerous_functions = dangerous_functions

    def analyze_code(self, code):
        """
        Function for checking code for dangerous functions:
        - Parses code into AST.
        - Traverses the tree and collects all violations.
        """

        try:
            tree = ast.parse(code)
        except Exception as e:
            return [{"error": f"Syntax error: {str(e)}"}]

        visitor = DangerousVisitor(self.dangerous_functions)
        visitor.visit(tree)
        return visitor.dangerous_calls


class DangerousVisitor(ast.NodeVisitor):
    def __init__(self, dangerous_functions):
        self.dangerous_calls = []
        self.dangerous_functions = dangerous_functions

    def visit_Call(self, node):
        """
        Check function calls:
        - If a function from the DANGEROUS_FUNCTIONS list is called, add an error message.
        - If the call is via an attribute (for example, os.system), then collect the full name and check it.
        """

        if isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Name
        ):
            func_name = f"{node.func.value.id}.{node.func.attr}"
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
        else:
            func_name = None

        if func_name in self.dangerous_functions:
            self.dangerous_calls.append(
                {
                    "line": node.lineno,
                    "function": func_name,
                    "message": f"Using a dangerous function: {func_name}",
                }
            )
        self.generic_visit(node)


class CodeCheckerApp:
    def __init__(self, root):
        self.root = root
        self.analyzer = CodeAnalyzer(DANGEROUS_FUNCTIONS)
        self.results = []
        self.draw()

    def draw(self):
        """Drawing the interface"""

        self.root.title("Checking code for vulnerabilities")
        self.root.geometry("800x600")

        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Notepad with tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Entering the code manually
        self.code_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.code_tab, text="Enter code")

        # Code input field
        self.code_input = scrolledtext.ScrolledText(
            self.code_tab, wrap=tk.WORD, width=80, height=15
        )
        self.code_input.pack(fill=tk.BOTH, expand=True)
        self.code_input.tag_configure("danger", background="yellow")

        # Adding a code example with vulnerabilities
        self.code_input.insert(tk.END, DANGEROUS_CODE)

        # Tab 2: File Upload
        self.file_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.file_tab, text="Checking the file")

        ttk.Label(self.file_tab, text="Select file to check:").pack(pady=10)
        ttk.Button(self.file_tab, text="Select file", command=self.load_file).pack()

        # Check button
        ttk.Button(main_frame, text="Check code", command=self.check_code).pack(pady=5)

        # List of results
        self.result_list = ttk.Treeview(
            main_frame,
            columns=("line", "message"),
            show="headings",
            selectmode="browse",
        )
        self.result_list.heading("line", text="Line")
        self.result_list.column("line", width=10)
        self.result_list.heading("message", text="Message")
        self.result_list.column("message", width=600)
        self.result_list.pack(fill=tk.BOTH, expand=True)
        self.result_list.bind("<<TreeviewSelect>>", self.on_result_select)

    def load_file(self):
        """Opens a file selection dialog"""

        file_path = filedialog.askopenfilename(
            initialdir="./code",
            filetypes=(("Python files", "*.py"), ("All files", "*.*")),
        )
        if not file_path or not os.path.isfile(file_path):
            self.result_text.insert(tk.END, "Error: Please select a valid file\n")
        else:
            with open(file_path, "r", encoding="utf-8") as f:
                self.code_input.delete(1.0, tk.END)
                self.code_input.insert(tk.END, f.read())
            # Switch to the "Enter Code" tab
            self.notebook.select(self.code_tab)
            # Clearing previous results
            self.result_list.delete(*self.result_list.get_children())

    def check_code(self):
        """
        The function called when the "Check Code" button is clicked:
        - Reads the code from the text field.
        - Checks the code.
        - Displays the results in a separate text field.
        """

        code = self.code_input.get(1.0, tk.END)
        results = self.analyzer.analyze_code(code)

        # Clearing previous results
        self.result_list.delete(*self.result_list.get_children())
        self.code_input.tag_remove("danger", 1.0, tk.END)

        # Filling the results list
        self.results = []
        if not results:
            good_message = "No dangerous functions found.\n"
            self.results.append({"line": 0, "message": good_message})
            self.result_list.insert("", tk.END, values=(0, good_message))

        for issue in results:
            if "error" in issue:
                self.results.append({"line": 0, "message": issue["error"]})
                self.result_list.insert("", tk.END, values=(0, issue["error"]))
            else:
                self.results.append(issue)
                self.result_list.insert(
                    "", tk.END, values=(issue["line"], issue["message"])
                )
                # Highlighting a line with vulnerability
                self.highlight_line(issue["line"])

        # Selecting the first element
        if self.results:
            self.result_list.selection_set(self.result_list.get_children()[0])
            self.result_list.focus(self.result_list.get_children()[0])

    def highlight_line(self, line_number):
        """Highlighting a line with vulnerability"""

        start = f"{line_number}.0"
        end = f"{line_number + 1}.0"
        self.code_input.tag_add("danger", start, end)

    def on_result_select(self, event):
        """Callback function of the results list"""

        selection = self.result_list.selection()
        if not selection:
            return

        index = self.result_list.index(selection[0])
        issue = self.results[index]

        if "line" in issue and issue["line"] > 0:
            self.code_input.tag_remove("danger", 1.0, tk.END)
            self.highlight_line(issue["line"])
            self.code_input.see(f"{issue['line']}.0")


if __name__ == "__main__":
    root = tk.Tk()
    app = CodeCheckerApp(root)
    root.mainloop()
