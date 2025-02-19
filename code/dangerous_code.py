import os
import shutil
import subprocess
import pickle
import marshal

# 1. eval - выполнение произвольного кода
user_input = input("Введите выражение: ")
result = eval(user_input)  # Опасность: выполнение любого кода
print("Результат eval:", result)

# 2. exec - выполнение произвольного кода
code = input("Введите код: ")
exec(code)  # Опасность: выполнение любых команд

# 3. os.system - выполнение системных команд
filename = input("Введите имя файла: ")
os.system(f"rm {filename}")  # Опасность: инъекция команд

# 4. subprocess.Popen - небезопасный вызов процессов
command = ["ping", input("Введите хост: ")]
subprocess.Popen(command, shell=True)  # Опасность: shell=True

# 5. open - небезопасная работа с файлами
path = input("Введите путь: ")
with open(path, "w") as f:  # Опасность: перезапись системных файлов
    f.write("Hacked!")

# 6. shutil.rmtree - удаление директорий
dir_to_delete = input("Удалить директорию: ")
shutil.rmtree(dir_to_delete)  # Опасность: удаление любых директорий

# 7. os.remove - удаление файлов
file_to_remove = input("Удалить файл: ")
os.remove(file_to_remove)  # Опасность: удаление любых файлов

# 8. pickle.load - десериализация данных
malicious_pickle = input("Введите pickle-данные: ")
pickle.loads(malicious_pickle.encode())  # Опасность: RCE через десериализацию

# 9. marshal.load - десериализация байткода
malicious_marshal = input("Введите marshal-данные: ")
marshal.loads(malicious_marshal.encode())  # Опасность: выполнение произвольного кода
