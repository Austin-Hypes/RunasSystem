# RunasSystem

# Overview
This project is a Windows privilege escalation tool that allows a user to launch any application as NT AUTHORITY/SYSTEM by leveraging an existing SYSTEM process token.

# Features ✨
✅ Automatic Admin Elevation - Relaunches itself with Administrator privileges if not already running as admin.
✅ Process Scanning - Takes a snapshot of all running processes and identifies those running as NT AUTHORITY/SYSTEM.
✅ Token Duplication - Extracts and duplicates a SYSTEM token from an existing SYSTEM process.
✅ Execute as SYSTEM - Uses the duplicated token to launch a specified application with SYSTEM privileges.

# How It Works 🔍
Admin Check & Relaunch:

The program first checks if it is running as Administrator.
If not, it restarts itself with elevated privileges using ShellExecuteExW().
Process Enumeration:

It captures a snapshot of all running processes.
It loops through the processes and checks the user of each process.
Finding a SYSTEM Process:

If it finds a process running as NT AUTHORITY/SYSTEM, it attempts to extract its access token.
Launching an Application as SYSTEM:

It duplicates the SYSTEM token and launches a user-specified application under that token.


# Disclaimer 🛑
This tool is meant for educational and administrative use only. Misuse of privilege escalation techniques can lead to security vulnerabilities or violations of IT policies.


# Notes 📝
Created In Visual Studio 2022 Using C++ Used Ctrl B to build
