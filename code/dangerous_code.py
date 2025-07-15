import os
import shutil
import subprocess
import pickle
import marshal

# 1. eval - arbitrary code execution
user_input = input("Enter expression: ")
result = eval(user_input)  # Danger: execution of any code
print("Result of eval:", result)

# 2. exec - arbitrary code execution
code = input("Enter the code: ")
exec(code)  # Danger: Execution of any commands

# 3. os.system - execution of system commands
filename = input("Enter file name: ")
os.system(f"rm {filename}")  # Danger: Command injection

# 4. subprocess.Popen - unsafe process invocation
command = ["ping", input("Enter host: ")]
subprocess.Popen(command, shell=True)  # Danger: shell=True

# 5. open - unsafe file handling
path = input("Enter path: ")
with open(path, "w") as f:  # Danger: Overwriting system files
    f.write("Hacked!")

# 6. shutil.rmtree - deleting directories
dir_to_delete = input("Delete directory: ")
shutil.rmtree(dir_to_delete)  # Danger: Deleting any directories

# 7. os.remove - deleting files
file_to_remove = input("Delete file: ")
os.remove(file_to_remove)  # Danger: Deletion of any files

# 8. pickle.load - data deserialization
malicious_pickle = input("Enter pickle data: ")
pickle.loads(malicious_pickle.encode())  # Danger: RCE via deserialization

# 9. marshal.load - bytecode deserialization
malicious_marshal = input("Enter marshal data: ")
marshal.loads(malicious_marshal.encode())  # Danger: Arbitrary code execution
