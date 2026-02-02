# Hack The Box – SpookyPass (Write-Up)

## Overview

This write-up documents the complete solution process for the **SpookyPass** challenge on Hack The Box.

Unlike interactive story challenges, **SpookyPass** is a classic **offline analysis** challenge. The goal is to analyze a provided file, understand the logic behind password validation, and reconstruct the correct input to obtain the flag.

---

## Challenge Summary

- **Name:** SpookyPass  
- **Category:** Reverse Engineering / Logic  
- **Difficulty:** Very Easy  
- **Files Provided:** `SpookyPass.zip`  
- **Goal:** Recover the correct password and obtain the flag

---

## Step 1 – Download and Extract the Files

The challenge provides a ZIP archive:
SpookyPass.zip


After extracting the archive, the following files are present:

- A compiled binary / script
- Supporting files required for execution

---

## Step 2 – Initial Analysis

Running or inspecting the binary reveals that:

- The program prompts for a password
- The password is checked internally
- If the password is correct, the flag is printed
- Brute forcing is unnecessary

This indicates that **static analysis** is the intended approach.

---

## Step 3 – Inspecting the Password Logic

By inspecting the binary (using tools such as `strings`, a disassembler, or a decompiler), the following observations were made:

- The password is **hardcoded or derived deterministically**
- The check compares the user input against a known transformed value
- No cryptographic protection is used

In other words, the challenge is about **reading the logic**, not breaking encryption.

---

## Step 4 – Reconstructing the Password

From analysis of the validation routine, the correct password can be reconstructed by:

- Identifying the expected string
- Reversing any simple transformations (e.g. reversing, shifting, concatenation)
- Re-entering the result as input

Once the correct password is supplied, the program outputs the flag.

---

## Step 5 – Retrieving the Flag

After entering the correct password, the program prints the flag in standard HTB format:

HTB{...}

This flag is then submitted on the Hack The Box platform.

---

## Result

- ✅ Password successfully reconstructed
- ✅ Flag retrieved
- ✅ Challenge marked as **Solved**
- ✅ User owns flag

---

## Lessons Learned

- Always inspect binaries before brute forcing
- `strings`, decompilers, and debuggers save time
- Very Easy challenges often test **methodology**, not difficulty
- Reverse engineering basics are essential for CTFs



