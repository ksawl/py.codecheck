# **Check Python scripts for vulnerabilities and malicious code**

> A simple program that checks code for dangerous functions, such as `eval()` or `os.system()`.

---

## 1. **Description of the program's functionality**

The program allows you to:

-   Check code for dangerous functions
-   Select a file to check (by default from `./code/*.py`)
-   Enter code manually (with a preset example)
-   Switch between tabs (file/manual entry)

---

## 2. **Understanding the problem**

Some Python functions can be dangerous if used without proper checking:

1. **Code injection**
   `eval()`, `exec()` – execute arbitrary code (can run malicious commands).
2. **Execute arbitrary commands**
   `os.system()`, `subprocess.Popen()` – execute system commands.
3. **Access to the file system**
   `open()`, `shutil.rmtree()`, `os.remove()` – can delete files.
4. **Loading data**
   `pickle.load()` – can execute code when loading data.

---

## 3. **Using AST (Abstract Syntax Tree)**

The `ast` module is used for static code analysis without executing it.

This is a safe way to parse code and find dangerous nodes, since it **does not execute code**, but only analyzes it.

### **How does it work?**

1. We parse the code in AST (Abstract Syntax Tree).
2. We go through the tree nodes and check function calls.
3. If we find the use of dangerous functions, we report it.

---

## 4. **Limitations of the approach**

1. **Static analysis** will not catch dynamically created function names (e.g. `getattr(os, 'system')('ls')`).
2. **False positives**: Not all calls to `eval()` are dangerous (but it's better to be safe).
3. **Missed threats**: For example, using `pickle` or `yaml.load()`.

---

## 5. **Additional security improvements for your code**

1. **Argument checking**: For example, if `eval()` is called with a constant, it is less dangerous.
2. **Integration with linters**: Use `flake8` with plugins, for example `bandit` ([GitHub](https://github.com/PyCQA/bandit)).
3. **Dynamic Analysis**: Runs in a sandbox to track behavior.

---

## 6. **Program Description**

1. **Code Input Tab**:

-   The user can paste or write the code manually.
-   A sample code with vulnerabilities is inserted by default.

2. **File Check Tab**:

-   The user selects a file from the `./code` directory (by default).
-   The file contents are loaded into the text field.
-   After loading the file, the program will automatically switch to the "Code Input" tab, where the loaded code will be displayed.

3. **"Check Code" Button**:

-   Analyzes the code from the "Code Input" tab.
-   The check results are displayed in the "Results" field.

4. **Results**:

-   If dangerous functions are found, the program displays a list of them with the lines indicated.
-   The user can jump to the found error by clicking on the list item.
-   If there are no errors, the message "No dangerous functions found" is displayed.
-   Before each code check, the old highlighting is removed to avoid highlighting overlap.

---

### **Text check example**

1. Insert the code with vulnerabilities:

```python
import os
eval('print("Hello, World!")')
os.system('ls')
```

2. Click "Check code".

3. In the text field with the code, the lines with `eval` and `os.system` will be highlighted in yellow.

4. The message will appear in the results field:

```
Line 2: Use of dangerous function: eval
Line 3: Use of dangerous function: os.system
```

### **File check example**

1. Go to the "File check" tab.
2. Click "Select file" and select the file with the code.
3. After selecting the file, the program will switch to the "Enter code" tab, where the loaded code will be displayed.
4. Click "Check code" to see the analysis results and highlighting of vulnerabilities.

---

### **Running the program**

1. Save the code to a directory on your hard drive.
2. Create a `./code` directory and add Python files to it for checking.
3. Run the program:

```bash
python main.py
```

---

## 7. **Conclusion**

The created script is the basis for static analysis. For professional use, it is better to combine:

1. **Static analysis** (e.g. `bandit`, `pylint`).
2. **Dynamic analysis** (e.g. running in an isolated environment).
3. **Manual audit** for complex cases.

---
