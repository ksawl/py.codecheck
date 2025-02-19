import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import ast
import os

# Опасные функции
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

# Пример кода с уязвимостями
DANGEROUS_CODE = """# Пример кода с уязвимостями
import os
eval('print("Hello, World!")')
os.system('ls')
"""


class CodeAnalyzer:
    def __init__(self, dangerous_functions):
        self.dangerous_functions = dangerous_functions

    def analyze_code(self, code):
        """
        Функция для проверки кода на использование опасных функций:
        - Парсит код в AST.
        - Обходит дерево и собирает все нарушения.
        """

        try:
            tree = ast.parse(code)
        except Exception as e:
            return [{"error": f"Ошибка синтаксиса: {str(e)}"}]

        visitor = DangerousVisitor(self.dangerous_functions)
        visitor.visit(tree)
        return visitor.dangerous_calls


class DangerousVisitor(ast.NodeVisitor):
    def __init__(self, dangerous_functions):
        self.dangerous_calls = []
        self.dangerous_functions = dangerous_functions

    def visit_Call(self, node):
        """
        Проверяем вызовы функций:
        - Если вызывается функция из списка DANGEROUS_FUNCTIONS, добавляем сообщение об ошибке.
        - Если вызов через атрибут (например, os.system), то собираем полное имя и проверяем его.
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
                    "message": f"Использование опасной функции: {func_name}",
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
        """Отрисовка интерфейса"""

        self.root.title("Проверка кода на уязвимости")
        self.root.geometry("800x600")

        # Основной контейнер
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Блокнот с вкладками
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Вкладка 1: Ввод кода вручную
        self.code_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.code_tab, text="Ввод кода")

        # Поле ввода кода
        self.code_input = scrolledtext.ScrolledText(
            self.code_tab, wrap=tk.WORD, width=80, height=15
        )
        self.code_input.pack(fill=tk.BOTH, expand=True)
        self.code_input.tag_configure("danger", background="yellow")

        # Добавление примера кода с уязвимостями
        self.code_input.insert(tk.END, DANGEROUS_CODE)

        # Вкладка 2: Загрузка файла
        self.file_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.file_tab, text="Проверка файла")

        ttk.Label(self.file_tab, text="Выберите файл для проверки:").pack(pady=10)
        ttk.Button(self.file_tab, text="Выбрать файл", command=self.load_file).pack()

        # Кнопка проверки
        ttk.Button(main_frame, text="Проверить код", command=self.check_code).pack(
            pady=5
        )

        # Список результатов
        self.result_list = ttk.Treeview(
            main_frame,
            columns=("line", "message"),
            show="headings",
            selectmode="browse",
        )
        self.result_list.heading("line", text="Строка")
        self.result_list.column("line", width=10)
        self.result_list.heading("message", text="Сообщение")
        self.result_list.column("message", width=600)
        self.result_list.pack(fill=tk.BOTH, expand=True)
        self.result_list.bind("<<TreeviewSelect>>", self.on_result_select)

    def load_file(self):
        """Открывает диалог выбора файла"""

        file_path = filedialog.askopenfilename(
            initialdir="./code",
            filetypes=(("Python files", "*.py"), ("All files", "*.*")),
        )
        if not file_path or not os.path.isfile(file_path):
            self.result_text.insert(tk.END, "Ошибка: выберите корректный файл\n")
        else:
            with open(file_path, "r", encoding="utf-8") as f:
                self.code_input.delete(1.0, tk.END)
                self.code_input.insert(tk.END, f.read())
            # Переключение на вкладку "Ввод кода"
            self.notebook.select(self.code_tab)
            # Очистка предыдущих результатов
            self.result_list.delete(*self.result_list.get_children())

    def check_code(self):
        """
        Функция, вызываемая при нажатии кнопки "Проверить код":
        - Считывает код из текстового поля.
        - Проверяет код.
        - Выводит результаты в отдельном текстовом поле.
        """

        code = self.code_input.get(1.0, tk.END)
        results = self.analyzer.analyze_code(code)

        # Очистка предыдущих результатов
        self.result_list.delete(*self.result_list.get_children())
        self.code_input.tag_remove("danger", 1.0, tk.END)

        # Заполнение списка результатов
        self.results = []
        if not results:
            good_message = "Опасных функций не найдено.\n"
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
                # Подсветка строки с уязвимостью
                self.highlight_line(issue["line"])

        # Выделение первого элемента
        if self.results:
            self.result_list.selection_set(self.result_list.get_children()[0])
            self.result_list.focus(self.result_list.get_children()[0])

    def highlight_line(self, line_number):
        """Посветка строки с уязвимостью"""

        start = f"{line_number}.0"
        end = f"{line_number + 1}.0"
        self.code_input.tag_add("danger", start, end)

    def on_result_select(self, event):
        """Callback функция списка результатов"""

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
