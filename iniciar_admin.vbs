Set objShell = CreateObject("Shell.Application")
Set objFSO = CreateObject("Scripting.FileSystemObject")
strDir = objFSO.GetParentFolderName(WScript.ScriptFullName)
objShell.ShellExecute "cmd.exe", "/c cd /d """ & strDir & """ && """ & strDir & "\.venv\Scripts\python.exe"" run.py", strDir, "runas", 1
